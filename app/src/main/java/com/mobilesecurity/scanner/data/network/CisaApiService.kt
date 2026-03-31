package com.mobilesecurity.scanner.data.network

import com.mobilesecurity.scanner.data.network.dto.CisaKevResponse
import retrofit2.http.GET

interface CisaApiService {

    // CISA stellt die gesamte KEV-Liste als einzelnes JSON bereit
    @GET("known_exploited_vulnerabilities.json")
    suspend fun getKnownExploitedVulnerabilities(): CisaKevResponse
}
