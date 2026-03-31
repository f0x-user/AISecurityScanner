package com.mobilesecurity.scanner.di

import android.content.Context
import android.content.SharedPreferences
import com.mobilesecurity.scanner.data.db.AppDatabase
import com.mobilesecurity.scanner.data.db.dao.RemediationLogDao
import com.mobilesecurity.scanner.domain.remediation.RemediationEngine
import com.mobilesecurity.scanner.domain.snapshot.SnapshotManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object RemediationModule {

    @Provides
    @Singleton
    fun provideRemediationLogDao(db: AppDatabase): RemediationLogDao =
        db.remediationLogDao()

    @Provides
    @Singleton
    fun provideSnapshotManager(encryptedPrefs: SharedPreferences): SnapshotManager =
        SnapshotManager(encryptedPrefs)

    @Provides
    @Singleton
    fun provideRemediationEngine(
        @ApplicationContext context: Context,
        remediationLogDao: RemediationLogDao,
        snapshotManager: SnapshotManager
    ): RemediationEngine = RemediationEngine(context, remediationLogDao, snapshotManager)
}
