package com.aisecurity.scanner.data.network

import com.aisecurity.scanner.data.network.dto.OsvQueryRequest
import com.aisecurity.scanner.data.network.dto.OsvResponse
import retrofit2.http.Body
import retrofit2.http.POST

interface OsvApiService {

    @POST("v1/query")
    suspend fun queryVulnerabilities(
        @Body request: OsvQueryRequest
    ): OsvResponse
}
