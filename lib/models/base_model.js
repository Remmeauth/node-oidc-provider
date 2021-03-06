/* eslint-disable max-classes-per-file */

const IN_PAYLOAD = [
  'iat',
  'exp',
  'jti',
  'kind',
];

const { strict: assert } = require('assert');

const assign = require('lodash/assign');
const pickBy = require('lodash/pickBy');
const snakeCase = require('lodash/snakeCase');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).Adapter)(obj.name));
    }

    return adapterCache.get(obj);
  }

  class Class {
    constructor({ jti, kind, ...payload } = {}) {
      assign(this, pickBy(
        payload,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key),
      ));

      assert(!kind || kind === this.constructor.name, 'kind mismatch');

      this.kind = kind || this.constructor.name;
      this.jti = jti;
    }

    async save(ttl) {
      if (!this.jti) {
        this.jti = this.generateTokenId();
      }

      // this is true for all BaseToken descendants
      if (typeof this.constructor.expiresIn !== 'function') {
        this.exp = epochTime() + ttl;
      }

      const [token, upsert] = await this.getValueAndPayload();

      await this.adapter.upsert(this.jti, upsert, ttl);
      this.emit('saved');

      return token;
    }

    async destroy() {
      if (process.env.SESSION_MODE === 'token' && this.kind === 'Session' && this.account) {
        await this.adapter.destroy(this.jti + ':' + this.account);
      } else {
        await this.adapter.destroy(this.jti);
      }
      this.emit('destroyed');
    }

    static get adapter() {
      return adapter(this);
    }

    get adapter() {
      return adapter(this);
    }

    static get IN_PAYLOAD() { return IN_PAYLOAD; }

    static async findAll(value, mask = false, ignoreExpiration = false) {
      let jti;
      try {
        jti = this.getTokenId(value);
        assert(jti);
      } catch (err) {
        return undefined;
      }

      let list = [];
      let keys;
      if (mask) {
        keys = await this.adapter.getAll(false, mask);
      } else {
        keys = await this.adapter.getAll(jti);
      }

      for (const item of keys) {
        const stored = await this.adapter.find(item.replace(`oidc:${this.name}:`, ``));
        if (stored) {
          list.push(new this(stored));
        }
      }
      return list;
    }

    static async find(value, { ignoreExpiration = false } = {}, prefix = '') {
      if (typeof value !== 'string') {
        return undefined;
      }

      let jti;
      try {
        jti = this.getTokenId(value);
        assert(jti);
      } catch (err) {
        return undefined;
      }
      
      const stored = await this.adapter.find(jti + `${prefix ? ':' + prefix : prefix}`);

      try {
        assert(stored);
        const payload = await this.verify(value, stored, { ignoreExpiration });
        assert.equal(jti, payload.jti);

        return new this(payload);
      } catch (err) {
        return undefined;
      }
    }

    emit(eventName) {
      provider.emit(`${snakeCase(this.kind)}.${eventName}`, this);
    }
  }

  class BaseModel extends hasFormat(provider, 'base', Class) {}

  return BaseModel;
};
