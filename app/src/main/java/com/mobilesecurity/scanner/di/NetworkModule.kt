package com.mobilesecurity.scanner.di

import com.mobilesecurity.scanner.data.network.CisaApiService
import com.mobilesecurity.scanner.data.network.HibpApiService
import com.mobilesecurity.scanner.data.network.NvdApiService
import com.mobilesecurity.scanner.data.network.PwnedPasswordsApiService
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideMoshi(): Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .apply {
            // Logging nur im Debug-Build
            if (com.mobilesecurity.scanner.BuildConfig.DEBUG) {
                addInterceptor(HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BASIC
                })
            }
        }
        .build()

    @Provides
    @Singleton
    @Named("nvd")
    fun provideNvdRetrofit(okHttpClient: OkHttpClient, moshi: Moshi, nvdKeyProvider: NvdKeyProvider): Retrofit {
        val nvdClient = okHttpClient.newBuilder()
            .addInterceptor { chain ->
                val request = chain.request()
                val key = nvdKeyProvider.getApiKey()
                val newRequest = if (key.isNotEmpty()) {
                    request.newBuilder().addHeader("apiKey", key).build()
                } else request
                chain.proceed(newRequest)
            }
            .build()
        return Retrofit.Builder()
            .baseUrl("https://services.nvd.nist.gov/rest/json/")
            .client(nvdClient)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
    }

    @Provides
    @Singleton
    @Named("cisa")
    fun provideCisaRetrofit(okHttpClient: OkHttpClient, moshi: Moshi): Retrofit =
        Retrofit.Builder()
            .baseUrl("https://www.cisa.gov/sites/default/files/feeds/")
            .client(okHttpClient)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()

    @Provides
    @Singleton
    fun provideNvdApiService(@Named("nvd") retrofit: Retrofit): NvdApiService =
        retrofit.create(NvdApiService::class.java)

    @Provides
    @Singleton
    fun provideCisaApiService(@Named("cisa") retrofit: Retrofit): CisaApiService =
        retrofit.create(CisaApiService::class.java)

    @Provides
    @Singleton
    @Named("hibp")
    fun provideHibpRetrofit(okHttpClient: OkHttpClient, moshi: Moshi): Retrofit =
        Retrofit.Builder()
            .baseUrl("https://haveibeenpwned.com/api/v3/")
            .client(okHttpClient)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()

    @Provides
    @Singleton
    @Named("pwned")
    fun providePwnedPasswordsRetrofit(okHttpClient: OkHttpClient, moshi: Moshi): Retrofit =
        Retrofit.Builder()
            .baseUrl("https://api.pwnedpasswords.com/")
            .client(
                okHttpClient.newBuilder()
                    .addInterceptor { chain ->
                        val req = chain.request().newBuilder()
                            .addHeader("Add-Padding", "true")
                            .build()
                        chain.proceed(req)
                    }
                    .build()
            )
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()

    @Provides
    @Singleton
    fun provideHibpApiService(@Named("hibp") retrofit: Retrofit): HibpApiService =
        retrofit.create(HibpApiService::class.java)

    @Provides
    @Singleton
    fun providePwnedPasswordsApiService(@Named("pwned") retrofit: Retrofit): PwnedPasswordsApiService =
        retrofit.create(PwnedPasswordsApiService::class.java)
}
