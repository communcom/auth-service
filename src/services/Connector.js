const core = require('cyberway-core-service');
const BasicConnector = core.services.Connector;

const Auth = require('../controllers/Auth');

class Connector extends BasicConnector {
    constructor() {
        super();

        this._auth = new Auth({ connector: this });
    }

    async start() {
        await super.start({
            serverRoutes: {
                'auth.generateSecret': {
                    handler: this._auth.generateSecret,
                    scope: this._auth,
                    validation: {
                        required: ['channelId'],
                        properties: {
                            channelId: {
                                type: 'string',
                            },
                        },
                    },
                },
                'auth.authorize': {
                    handler: this._auth.authorize,
                    scope: this._auth,
                    validation: {
                        required: ['user', 'sign', 'secret', 'channelId'],
                        properties: {
                            user: {
                                type: 'string',
                            },
                            secret: {
                                type: 'string',
                            },
                            sign: {
                                type: 'string',
                            },
                            channelId: {
                                type: 'string',
                            },
                        },
                    },
                },
                'auth.getPublicKeys': {
                    handler: this._auth.getPublicKeys,
                    required: ['userId'],
                    scope: this._auth,
                    validation: {
                        properties: {
                            userId: {
                                type: 'string',
                            },
                        },
                    },
                },
            },
        });
    }
}

module.exports = Connector;
