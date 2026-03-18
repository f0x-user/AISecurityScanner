package com.aisecurity.scanner.di

import android.content.Context
import androidx.room.Room
import com.aisecurity.scanner.data.db.AppDatabase
import com.aisecurity.scanner.data.db.dao.*
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideAppDatabase(
        @ApplicationContext context: Context,
        keyProvider: DatabaseKeyProvider
    ): AppDatabase {
        // Native SQLCipher-Bibliothek laden (Pflicht für sqlcipher-android)
        System.loadLibrary("sqlcipher")
        val passphrase = keyProvider.getOrCreatePassphrase()
        val factory = SupportOpenHelperFactory(passphrase)
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "aisecurity_scanner.db"
        )
            .openHelperFactory(factory)
            .addMigrations(AppDatabase.MIGRATION_2_3)
            .build()
    }

    @Provides
    fun provideScanResultDao(db: AppDatabase): ScanResultDao = db.scanResultDao()

    @Provides
    fun provideVulnerabilityDao(db: AppDatabase): VulnerabilityDao = db.vulnerabilityDao()

    @Provides
    fun provideCVECacheDao(db: AppDatabase): CVECacheDao = db.cveCache()

    @Provides
    fun provideAppAuditDao(db: AppDatabase): AppAuditDao = db.appAuditDao()
}
