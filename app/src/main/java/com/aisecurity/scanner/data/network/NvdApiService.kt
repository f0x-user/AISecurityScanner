package com.aisecurity.scanner.data.network

import com.aisecurity.scanner.data.network.dto.NvdResponse
import retrofit2.http.GET
import retrofit2.http.Query

interface NvdApiService {

    @GET("cves/2.0")
    suspend fun searchCves(
        @Query("keywordSearch") keyword: String = "android",
        @Query("pubStartDate") pubStartDate: String? = null,
        @Query("pubEndDate") pubEndDate: String? = null,
        @Query("resultsPerPage") resultsPerPage: Int = 100,
        @Query("startIndex") startIndex: Int = 0
    ): NvdResponse

    @GET("cves/2.0")
    suspend fun getCveById(
        @Query("cveId") cveId: String
    ): NvdResponse
}
