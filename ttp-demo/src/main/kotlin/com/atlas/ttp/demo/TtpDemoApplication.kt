package com.atlas.ttp.demo

import android.app.Application
import timber.log.Timber

/**
 * Application class for TTP Demo app.
 */
class TtpDemoApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize Timber for logging
        if (Timber.treeCount == 0) {
            Timber.plant(Timber.DebugTree())
        }

        Timber.d("TTP Demo Application started")
    }
}
