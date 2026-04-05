package com.mobilesecurity.scanner.data.network

import com.mobilesecurity.scanner.data.network.dto.GithubRelease
import retrofit2.Response
import retrofit2.http.GET

interface GithubApiService {

    @GET("repos/f0x-user/AISecurityScanner/releases/latest")
    suspend fun getLatestRelease(): Response<GithubRelease>
}
