export type HttpResponse = {
    statusCode?: number
    response: string
}

export function httpRequest(
    authUrlOrigin: URL,
    apiKey: string,
    path: string,
    method: string,
    body?: string
): Promise<HttpResponse> {
    let userAgent = `propelauth-node/${process.env.npm_package_version} node/${process.version} ${process.platform}/${process.arch}`
    let headers: any = {
        Authorization: "Bearer " + apiKey,
        "Content-Type": "application/json",
        "User-Agent": userAgent,
    }

    return fetch(authUrlOrigin.origin + path, {
        method,
        headers,
        body,
    }).then(response => {
        return response.text().then(res => {
            return {
                statusCode: response.status,
                response: res,
            }
        })
    })
}