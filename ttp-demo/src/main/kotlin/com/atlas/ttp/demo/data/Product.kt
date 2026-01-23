package com.atlas.ttp.demo.data

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * Represents a product in the catalog.
 *
 * @property id Unique identifier for the product
 * @property name Display name of the product
 * @property description Short description
 * @property priceInCents Price in cents (e.g., 450 = $4.50)
 * @property category Product category for filtering
 * @property icon Material icon to represent the product
 */
data class Product(
    val id: String,
    val name: String,
    val description: String,
    val priceInCents: Long,
    val category: ProductCategory,
    val icon: ImageVector
) {
    val formattedPrice: String
        get() = "$${priceInCents / 100}.${(priceInCents % 100).toString().padStart(2, '0')}"
}

enum class ProductCategory(val displayName: String) {
    COFFEE("Coffee"),
    TEA("Tea"),
    PASTRY("Pastries"),
    SANDWICH("Sandwiches"),
    OTHER("Other")
}

/**
 * Represents an item in the shopping cart.
 */
data class CartItem(
    val product: Product,
    val quantity: Int
) {
    val totalPriceInCents: Long
        get() = product.priceInCents * quantity

    val formattedTotalPrice: String
        get() = "$${totalPriceInCents / 100}.${(totalPriceInCents % 100).toString().padStart(2, '0')}"
}
