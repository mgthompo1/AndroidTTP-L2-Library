package com.atlas.ttp.demo.viewmodel

import android.app.Activity
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.atlas.ttp.demo.data.CartState
import com.atlas.ttp.demo.data.Product
import com.atlas.ttp.demo.payment.PaymentProcessor
import com.atlas.ttp.demo.payment.PaymentResult
import com.atlas.ttp.demo.payment.PaymentStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * ViewModel managing the POS app state including cart, checkout, and payment processing.
 */
class PosViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(PosUiState())
    val uiState: StateFlow<PosUiState> = _uiState.asStateFlow()

    private var paymentProcessor: PaymentProcessor? = null

    /**
     * Initialize the payment processor with the activity context.
     * Must be called from the Activity's onCreate.
     */
    fun initializePaymentProcessor(activity: Activity) {
        if (paymentProcessor == null) {
            paymentProcessor = PaymentProcessor(activity)
            Timber.d("Payment processor initialized")
        }
    }

    /**
     * Enable NFC foreground dispatch. Call from Activity's onResume.
     */
    fun enableNfc() {
        paymentProcessor?.enableNfc()
    }

    /**
     * Disable NFC foreground dispatch. Call from Activity's onPause.
     */
    fun disableNfc() {
        paymentProcessor?.disableNfc()
    }

    /**
     * Handle NFC intent from Activity's onNewIntent.
     */
    fun handleNfcIntent(intent: Intent) {
        paymentProcessor?.handleIntent(intent)
    }

    // Cart operations

    fun addToCart(product: Product) {
        _uiState.update { state ->
            state.copy(cartState = state.cartState.addItem(product))
        }
        Timber.d("Added ${product.name} to cart")
    }

    fun removeFromCart(productId: String) {
        _uiState.update { state ->
            state.copy(cartState = state.cartState.removeItem(productId))
        }
    }

    fun incrementQuantity(productId: String) {
        _uiState.update { state ->
            state.copy(cartState = state.cartState.incrementQuantity(productId))
        }
    }

    fun decrementQuantity(productId: String) {
        _uiState.update { state ->
            state.copy(cartState = state.cartState.decrementQuantity(productId))
        }
    }

    fun clearCart() {
        _uiState.update { state ->
            state.copy(cartState = state.cartState.clear())
        }
    }

    // Navigation

    fun navigateTo(screen: Screen) {
        _uiState.update { it.copy(currentScreen = screen) }
    }

    fun navigateToCart() {
        navigateTo(Screen.Cart)
    }

    fun navigateToCatalog() {
        navigateTo(Screen.Catalog)
    }

    fun navigateBack() {
        val currentScreen = _uiState.value.currentScreen
        val newScreen = when (currentScreen) {
            Screen.Cart -> Screen.Catalog
            Screen.Checkout -> Screen.Cart
            Screen.Receipt -> Screen.Catalog // Go back to catalog from receipt
            Screen.Catalog -> Screen.Catalog
        }
        navigateTo(newScreen)
    }

    // Checkout and payment

    fun startCheckout() {
        if (_uiState.value.cartState.isEmpty) {
            Timber.w("Cannot checkout with empty cart")
            return
        }

        _uiState.update { state ->
            state.copy(
                currentScreen = Screen.Checkout,
                paymentStatus = PaymentStatus.WaitingForCard,
                paymentResult = null
            )
        }

        // Start payment processing
        startPaymentProcessing()
    }

    private fun startPaymentProcessing() {
        val processor = paymentProcessor
        if (processor == null) {
            Timber.e("Payment processor not initialized")
            _uiState.update { state ->
                state.copy(
                    paymentResult = PaymentResult.Error("Payment processor not initialized"),
                    currentScreen = Screen.Receipt,
                    transactionTimestamp = System.currentTimeMillis()
                )
            }
            return
        }

        val amountInCents = _uiState.value.cartState.totalInCents

        viewModelScope.launch {
            try {
                val result = processor.processPayment(
                    amountInCents = amountInCents,
                    onStatusUpdate = { status ->
                        _uiState.update { it.copy(paymentStatus = status) }
                    }
                )

                _uiState.update { state ->
                    state.copy(
                        paymentResult = result,
                        currentScreen = Screen.Receipt,
                        transactionTimestamp = System.currentTimeMillis()
                    )
                }

                Timber.d("Payment completed: $result")
            } catch (e: Exception) {
                Timber.e(e, "Payment processing error")
                _uiState.update { state ->
                    state.copy(
                        paymentResult = PaymentResult.Error(e.message ?: "Unknown error"),
                        currentScreen = Screen.Receipt,
                        transactionTimestamp = System.currentTimeMillis()
                    )
                }
            }
        }
    }

    fun cancelPayment() {
        navigateTo(Screen.Cart)
        _uiState.update { state ->
            state.copy(
                paymentStatus = PaymentStatus.WaitingForCard,
                paymentResult = null
            )
        }
    }

    fun startNewTransaction() {
        _uiState.update {
            PosUiState() // Reset to initial state
        }
    }

    // Check NFC availability
    fun isNfcAvailable(): Boolean = paymentProcessor?.isNfcAvailable() == true
    fun isNfcEnabled(): Boolean = paymentProcessor?.isNfcEnabled() == true
}

/**
 * UI state for the POS app.
 */
data class PosUiState(
    val currentScreen: Screen = Screen.Catalog,
    val cartState: CartState = CartState(),
    val paymentStatus: PaymentStatus = PaymentStatus.WaitingForCard,
    val paymentResult: PaymentResult? = null,
    val transactionTimestamp: Long = 0L
)

/**
 * App screens/navigation destinations.
 */
enum class Screen {
    Catalog,
    Cart,
    Checkout,
    Receipt
}
