/**
 * Copyright (c) 2021 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */

import { AuthProviderInfo } from "@gitpod/gitpod-protocol";
import { log } from "@gitpod/gitpod-protocol/lib/util/logging";
import BitbucketServer = require("@atlassian/bitbucket-server")
import * as express from "express";
import { injectable } from "inversify";
import { AuthUserSetup } from "../auth/auth-provider";
import { GenericAuthProvider } from "../auth/generic-auth-provider";
import { BitbucketServerOAuthScopes } from "./bitbucket-server-oauth-scopes";
import fetch from "node-fetch";

 @injectable()
 export class BitbucketServerAuthProvider extends GenericAuthProvider {

    get info(): AuthProviderInfo {
        return {
            ...this.defaultInfo(),
            scopes: BitbucketServerOAuthScopes.ALL,
            requirements: {
                default: BitbucketServerOAuthScopes.Requirements.DEFAULT,
                publicRepo: BitbucketServerOAuthScopes.Requirements.DEFAULT,
                privateRepo: BitbucketServerOAuthScopes.Requirements.DEFAULT,
            },
        }
    }

    /**
     * Augmented OAuthConfig for Bitbucket
     */
    protected get oauthConfig() {
        const oauth = this.params.oauth!;
        const scopeSeparator = " ";
        return <typeof oauth>{
            ...oauth,
            authorizationUrl: oauth.authorizationUrl || `https://${this.params.host}/rest/oauth2/latest/authorize`,
            tokenUrl: oauth.tokenUrl || `https://${this.params.host}/rest/oauth2/latest/token`,
            settingsUrl: oauth.settingsUrl || `https://${this.params.host}/plugins/servlet/oauth/users/access-tokens/`,
            scope: BitbucketServerOAuthScopes.ALL.join(scopeSeparator),
            scopeSeparator
        };
    }

    protected get tokenUsername(): string {
        return "x-token-auth";
    }

    authorize(req: express.Request, res: express.Response, next: express.NextFunction, scope?: string[]): void {
        super.authorize(req, res, next, scope ? scope : BitbucketServerOAuthScopes.Requirements.DEFAULT);
    }

    protected readAuthUserSetup = async (accessToken: string, _tokenResponse: object) => {
        try {

            const fetchResult = await fetch(`https://${this.params.host}/plugins/servlet/applinks/whoami`,);
            if (!fetchResult.ok) {
                throw new Error(fetchResult.statusText);
            }
            const username = await fetchResult.text();

            const options = {
                baseUrl: `https://${this.params.host}`,
            };
            const client = new BitbucketServer(options);

            client.authenticate({type: "token", token: accessToken});
            const result = await client.api.getUser({userSlug: username});

            const user = result.data;
            const headers = result.headers;

            const primaryEmail = user.emailAddress!;

            // const currentScopes = this.normalizeScopes((headers as any)["x-oauth-scopes"]
            //     .split(",")
            //     .map((s: string) => s.trim())
            // );
            log.warn(`(${this.strategyName}) headers`, headers);

            return <AuthUserSetup>{
                authUser: {
                    authId: user.account_id,
                    authName: user.username,
                    primaryEmail: primaryEmail,
                    name: user.display_name,
                    avatarUrl: user.links!.avatar!.href
                },
                currentScopes: BitbucketServerOAuthScopes.ALL, // TODO
            }

        } catch (error) {
            log.error(`(${this.strategyName}) Reading current user info failed`, error, { accessToken, error });
            throw error;
        }
    }

    protected normalizeScopes(scopes: string[]) {
        const set = new Set(scopes);
        for (const item of set.values()) {
            if (!(BitbucketServerOAuthScopes.Requirements.DEFAULT.includes(item))) {
                set.delete(item);
            }
        }
        return Array.from(set).sort();
    }
 }