package com.atlas.ttp.demo

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.*
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.atlas.ttp.demo.ui.screens.*
import com.atlas.ttp.demo.ui.theme.TtpDemoTheme
import com.atlas.ttp.demo.viewmodel.PosViewModel
import com.atlas.ttp.demo.viewmodel.Screen

/**
 * Main activity for the TTP Demo app.
 *
 * Implements a full-featured point-of-sale demo showcasing the Atlas SoftPOS SDK
 * capabilities for contactless payment processing.
 */
class MainActivity : ComponentActivity() {

    private lateinit var posViewModel: PosViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            TtpDemoTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel: PosViewModel = viewModel()
                    posViewModel = viewModel

                    // Initialize payment processor
                    viewModel.initializePaymentProcessor(this)

                    // Check NFC availability
                    if (!viewModel.isNfcAvailable()) {
                        Toast.makeText(
                            this,
                            "NFC not available on this device",
                            Toast.LENGTH_LONG
                        ).show()
                    } else if (!viewModel.isNfcEnabled()) {
                        Toast.makeText(
                            this,
                            "Please enable NFC in settings",
                            Toast.LENGTH_LONG
                        ).show()
                    }

                    TtpDemoApp(viewModel = viewModel)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::posViewModel.isInitialized) {
            posViewModel.enableNfc()
        }
    }

    override fun onPause() {
        super.onPause()
        if (::posViewModel.isInitialized) {
            posViewModel.disableNfc()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (::posViewModel.isInitialized) {
            posViewModel.handleNfcIntent(intent)
        }
    }
}

@Composable
fun TtpDemoApp(viewModel: PosViewModel) {
    val uiState by viewModel.uiState.collectAsState()

    AnimatedContent(
        targetState = uiState.currentScreen,
        transitionSpec = {
            when {
                targetState.ordinal > initialState.ordinal -> {
                    // Moving forward
                    slideInHorizontally { width -> width } + fadeIn() togetherWith
                            slideOutHorizontally { width -> -width } + fadeOut()
                }
                else -> {
                    // Moving backward
                    slideInHorizontally { width -> -width } + fadeIn() togetherWith
                            slideOutHorizontally { width -> width } + fadeOut()
                }
            }.using(SizeTransform(clip = false))
        },
        label = "screen_transition"
    ) { screen ->
        when (screen) {
            Screen.Catalog -> CatalogScreen(
                cartItemCount = uiState.cartState.itemCount,
                onAddToCart = viewModel::addToCart,
                onViewCart = viewModel::navigateToCart
            )

            Screen.Cart -> CartScreen(
                cartState = uiState.cartState,
                onBackClick = viewModel::navigateToCatalog,
                onCheckout = viewModel::startCheckout,
                onIncrementItem = viewModel::incrementQuantity,
                onDecrementItem = viewModel::decrementQuantity,
                onRemoveItem = viewModel::removeFromCart
            )

            Screen.Checkout -> CheckoutScreen(
                cartState = uiState.cartState,
                paymentStatus = uiState.paymentStatus,
                onBackClick = viewModel::cancelPayment,
                onCancelPayment = viewModel::cancelPayment
            )

            Screen.Receipt -> {
                val result = uiState.paymentResult
                if (result != null) {
                    ReceiptScreen(
                        paymentResult = result,
                        cartState = uiState.cartState,
                        transactionTimestamp = uiState.transactionTimestamp,
                        onNewTransaction = viewModel::startNewTransaction
                    )
                }
            }
        }
    }
}
