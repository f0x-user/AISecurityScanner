package com.mobilesecurity.scanner.di

import android.content.Context
import com.mobilesecurity.scanner.data.network.HibpApiService
import com.mobilesecurity.scanner.data.network.PwnedPasswordsApiService
import com.mobilesecurity.scanner.data.repository.SettingsRepository
import com.mobilesecurity.scanner.data.repository.VulnerabilityRepository
import com.mobilesecurity.scanner.domain.scanner.*
import com.mobilesecurity.scanner.util.DebugLogger
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object ScannerModule {

    @Provides
    @Singleton
    fun provideSystemInfoScanner(@ApplicationContext context: Context): SystemInfoScanner =
        SystemInfoScanner(context)

    @Provides
    @Singleton
    fun provideAppPermissionAuditor(@ApplicationContext context: Context): AppPermissionAuditor =
        AppPermissionAuditor(context)

    @Provides
    @Singleton
    fun provideNetworkSecurityScanner(@ApplicationContext context: Context): NetworkSecurityScanner =
        NetworkSecurityScanner(context)

    @Provides
    @Singleton
    fun provideDeviceHardeningChecker(@ApplicationContext context: Context): DeviceHardeningChecker =
        DeviceHardeningChecker(context)

    @Provides
    @Singleton
    fun provideStorageSecurityScanner(@ApplicationContext context: Context): StorageSecurityScanner =
        StorageSecurityScanner(context)

    @Provides
    @Singleton
    fun provideZeroDayCorrelator(
        vulnRepository: VulnerabilityRepository,
        settingsRepository: SettingsRepository
    ): ZeroDayCorrelator = ZeroDayCorrelator(vulnRepository, settingsRepository)

    @Provides
    @Singleton
    fun provideMalwareIndicatorScanner(@ApplicationContext context: Context): MalwareIndicatorScanner =
        MalwareIndicatorScanner(context)

    @Provides
    @Singleton
    fun providePrivacyHardwareScanner(@ApplicationContext context: Context): PrivacyHardwareScanner =
        PrivacyHardwareScanner(context)

    @Provides
    @Singleton
    fun providePasswordLeakScanner(@ApplicationContext context: Context): PasswordLeakScanner =
        PasswordLeakScanner(context)

    @Provides
    @Singleton
    fun providePlayIntegrityScanner(@ApplicationContext context: Context): PlayIntegrityScanner =
        PlayIntegrityScanner(context)

    @Provides
    @Singleton
    fun provideKernelVisibilityScanner(@ApplicationContext context: Context): KernelVisibilityScanner =
        KernelVisibilityScanner(context)

    @Provides
    @Singleton
    fun provideBackdoorScanner(@ApplicationContext context: Context): BackdoorScanner =
        BackdoorScanner(context)

    @Provides
    @Singleton
    fun provideBreachCheckScanner(
        @ApplicationContext context: Context,
        hibpApiService: HibpApiService,
        pwnedPasswordsApiService: PwnedPasswordsApiService
    ): BreachCheckScanner = BreachCheckScanner(context, hibpApiService, pwnedPasswordsApiService)

    @Provides
    @Singleton
    fun provideSecurityScanManager(
        systemInfoScanner: SystemInfoScanner,
        appPermissionAuditor: AppPermissionAuditor,
        networkSecurityScanner: NetworkSecurityScanner,
        deviceHardeningChecker: DeviceHardeningChecker,
        storageSecurityScanner: StorageSecurityScanner,
        zeroDayCorrelator: ZeroDayCorrelator,
        malwareIndicatorScanner: MalwareIndicatorScanner,
        privacyHardwareScanner: PrivacyHardwareScanner,
        passwordLeakScanner: PasswordLeakScanner,
        playIntegrityScanner: PlayIntegrityScanner,
        kernelVisibilityScanner: KernelVisibilityScanner,
        backdoorScanner: BackdoorScanner,
        breachCheckScanner: BreachCheckScanner,
        debugLogger: DebugLogger
    ): SecurityScanManager = SecurityScanManager(
        systemInfoScanner,
        appPermissionAuditor,
        networkSecurityScanner,
        deviceHardeningChecker,
        storageSecurityScanner,
        zeroDayCorrelator,
        malwareIndicatorScanner,
        privacyHardwareScanner,
        passwordLeakScanner,
        playIntegrityScanner,
        kernelVisibilityScanner,
        backdoorScanner,
        breachCheckScanner,
        debugLogger
    )
}
