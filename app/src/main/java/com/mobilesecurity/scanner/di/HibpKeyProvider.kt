package com.mobilesecurity.scanner.di

import com.mobilesecurity.scanner.BuildConfig
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class HibpKeyProvider @Inject constructor() {
    fun getApiKey(): String = BuildConfig.HIBP_API_KEY
}
