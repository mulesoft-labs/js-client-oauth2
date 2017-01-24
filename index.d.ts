declare class ClientOAuth2 {
  code: ClientOAuth2.CodeFlow;
  token: ClientOAuth2.TokenFlow;
  owner: ClientOAuth2.OwnerFlow;
  credentials: ClientOAuth2.CredentialsFlow;
  jwt: ClientOAuth2.JwtBearerFlow;

  constructor(options: ClientOAuth2.Options, request?: ClientOAuth2.Request);

  createToken(data: ClientOAuth2.Data): ClientOAuth2.Token;
  createToken(accessToken: string, data: ClientOAuth2.Data): ClientOAuth2.Token;
  createToken(accessToken: string, refreshToken: string, data: ClientOAuth2.Data): ClientOAuth2.Token;
  createToken(accessToken: string, refreshToken: string, type: string, data: ClientOAuth2.Data): ClientOAuth2.Token;
}

declare namespace ClientOAuth2 {
  export interface Data {
    [key: string]: string
  }

  export interface Options {
    clientId?: string
    clientSecret?: string
    accessTokenUri?: string
    authorizationUri?: string
    redirectUri?: string
    scopes?: string[]
    state?: string
    body?: {
      [key: string]: string | string[];
    };
    query?: {
      [key: string]: string | string[];
    };
    headers?: {
      [key: string]: string | string[];
    };
  }

  export interface Request {
    (method: string, url: string, body: string, headers: { [key: string]: string | string[] }): Promise<{ status: number, body: string }>;
  }

  export interface RequestObject {
    url: string;
    headers?: {
      [key: string]: string | string[];
    };
  }

  export interface UrlObject {
    hash?: string | {
      [key: string]: string | string[];
    };
    query?: string | {
      [key: string]: string | string[];
    }
    pathname?: string;
  }

  export class Token {
    client: ClientOAuth2;
    data: Data;
    tokenType: string;
    accessToken: string;
    refreshToken: string;

    constructor(client: ClientOAuth2, data: Data);
    expiresIn(duration: number | Date): Date;
    sign<T extends RequestObject>(requestObj: T): T;
    refresh(options?: Options): Promise<Token>;
    expired(): boolean;
  }

  export class CodeFlow {
    constructor(client: ClientOAuth2);
    getUri(options?: Options): string;
    getToken(uri: string | UrlObject, options?: Options): Promise<Token>;
  }

  export class TokenFlow {
    constructor(client: ClientOAuth2);
    getUri(options?: Options): string;
    getToken(uri: string | UrlObject, options?: Options): Promise<Token>;
  }

  export class OwnerFlow {
    constructor(client: ClientOAuth2);
    getToken(username: string, password: string, options?: Options): Promise<Token>;
  }

  export class CredentialsFlow {
    constructor(client: ClientOAuth2);
    getToken(options?: Options): Promise<Token>;
  }

  export class JwtBearerFlow {
    constructor(client: ClientOAuth2);
    getToken(token: string, options?: Options): Promise<Token>;
  }
}

export = ClientOAuth2;
