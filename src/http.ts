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
    let headers: any = {
        'Authorization': "Bearer " + apiKey,
        "Content-Type": "application/json",
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