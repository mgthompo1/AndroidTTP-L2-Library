package com.atlas.ttp.demo.data

/**
 * Represents the current state of the shopping cart.
 */
data class CartState(
    val items: Map<String, CartItem> = emptyMap()
) {
    val itemCount: Int
        get() = items.values.sumOf { it.quantity }

    val subtotalInCents: Long
        get() = items.values.sumOf { it.totalPriceInCents }

    val taxInCents: Long
        get() = (subtotalInCents * TAX_RATE).toLong()

    val totalInCents: Long
        get() = subtotalInCents + taxInCents

    val isEmpty: Boolean
        get() = items.isEmpty()

    val formattedSubtotal: String
        get() = formatCents(subtotalInCents)

    val formattedTax: String
        get() = formatCents(taxInCents)

    val formattedTotal: String
        get() = formatCents(totalInCents)

    fun addItem(product: Product): CartState {
        val existingItem = items[product.id]
        val newItem = if (existingItem != null) {
            existingItem.copy(quantity = existingItem.quantity + 1)
        } else {
            CartItem(product = product, quantity = 1)
        }
        return copy(items = items + (product.id to newItem))
    }

    fun removeItem(productId: String): CartState {
        return copy(items = items - productId)
    }

    fun updateQuantity(productId: String, quantity: Int): CartState {
        if (quantity <= 0) {
            return removeItem(productId)
        }
        val existingItem = items[productId] ?: return this
        return copy(items = items + (productId to existingItem.copy(quantity = quantity)))
    }

    fun incrementQuantity(productId: String): CartState {
        val existingItem = items[productId] ?: return this
        return updateQuantity(productId, existingItem.quantity + 1)
    }

    fun decrementQuantity(productId: String): CartState {
        val existingItem = items[productId] ?: return this
        return updateQuantity(productId, existingItem.quantity - 1)
    }

    fun clear(): CartState = CartState()

    companion object {
        const val TAX_RATE = 0.0875 // 8.75% tax rate

        fun formatCents(cents: Long): String {
            return "$${cents / 100}.${(cents % 100).toString().padStart(2, '0')}"
        }
    }
}
