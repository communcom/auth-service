const random = require('randomstring');
const crypto = require('crypto');
const fetch = require('node-fetch');

const core = require('cyberway-core-service');
const Basic = core.controllers.Basic;
const { Logger } = core.utils;

const { JsonRpc } = require('cyberwayjs');
const Signature = require('eosjs-ecc/lib/signature');
const { convertLegacyPublicKey } = require('cyberwayjs/dist/eosjs-numeric');

const env = require('../data/env');

const RPC = new JsonRpc(env.GLS_CYBERWAY_HTTP_URL, { fetch });

class Auth extends Basic {
    constructor({ connector }) {
        super({ connector });
        this._secretMap = new Map();
    }

    async generateSecret({ channelId }) {
        const existedSecret = this._secretMap.get(channelId);

        if (existedSecret) {
            return {
                secret: existedSecret.toString(),
            };
        }

        const seed = random.generate();
        const hash = crypto.createHash('sha1');
        const secret = hash
            .update(Buffer.from(seed + channelId))
            .digest()
            .toString('hex');

        const serializedSecret = Buffer.from(secret);
        this._secretMap.set(channelId, serializedSecret);

        return { secret };
    }

    async authorize({ user, sign, secret, channelId }) {
        const storedSecret = this._secretMap.get(channelId);
        const secretBuffer = Buffer.from(secret);

        if (!storedSecret) {
            Logger.error('Auth error -- stored secret does not exist');

            throw {
                code: 1102,
                message:
                    "There is no secret stored for this channelId. Probably, client's already authorized",
            };
        }

        if (!storedSecret.equals(secretBuffer)) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }

        const resolvedUserId = await this._resolveUserId(`${user}@commun`);

        const publicKeys = await this._getPublicKeyFromBc(resolvedUserId);

        const publicKeysPermission = this._verifyKeys({
            secretBuffer,
            sign,
            publicKeys,
        });

        if (!publicKeysPermission) {
            Logger.error(
                'Public key is not valid',
                JSON.stringify({ user, resolvedUserId, publicKeysPermission, publicKeys }, null, 2)
            );
            throw { code: 1104, message: 'Public key verification failed - access denied' };
        }
        this._secretMap.delete(channelId);

        return {
            // this field exists in the name of Backward compatibility
            user: resolvedUserId,
            username: user,
            userId: resolvedUserId,
            permission: publicKeysPermission,
        };
    }

    async getPublicKeys({ userId }) {
        const publicKeys = await this._getPublicKeyFromBc(userId, false);

        return {
            publicKeys,
        };
    }

    // TODO use state-reader
    async _resolveUserId(user) {
        try {
            const resolved = await RPC.fetch('/v1/chain/resolve_names', [user]);
            return resolved[0].resolved_username;
        } catch (error) {
            Logger.error(`Error resolve_names for (${user})`, error);
            throw { code: 1105, message: `Can't resolve name: ${user}` };
        }
    }

    _verifyKeys({ secretBuffer, sign, publicKeys }) {
        let signature;

        try {
            signature = Signature.from(sign);
        } catch (error) {
            throw {
                code: 1106,
                message: 'Sign is not a valid signature',
            };
        }

        for (const { publicKey, permission } of publicKeys) {
            try {
                const verified = signature.verify(secretBuffer, publicKey);
                if (verified) {
                    return permission;
                }
            } catch (error) {
                Logger.error('Key cannot be verified --', error.stack);
            }
        }

        return false;
    }

    // TODO use state-reader
    async _getPublicKeyFromBc(userId, convertLegacyKeys = true) {
        let accountData = null;

        try {
            accountData = await RPC.get_account(userId);
        } catch (error) {
            Logger.error(`Error get_account for (${userId}):`, error);
            throw { code: 1107, message: `Cannot get such account from BC: ${userId}` };
        }

        return accountData.permissions.map(permission => {
            let publicKey = null;

            if (permission.required_auth.keys.length) {
                const key = permission.required_auth.keys[0].key;
                publicKey = convertLegacyKeys ? convertLegacyPublicKey(key) : key;
            }

            return {
                publicKey,
                permission: permission.perm_name,
            };
        });
    }
}

module.exports = Auth;
