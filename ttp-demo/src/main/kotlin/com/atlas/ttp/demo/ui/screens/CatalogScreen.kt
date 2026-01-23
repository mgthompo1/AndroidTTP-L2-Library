package com.atlas.ttp.demo.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ShoppingCart
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.atlas.ttp.demo.data.Product
import com.atlas.ttp.demo.data.SampleProducts
import com.atlas.ttp.demo.ui.components.ProductCard
import com.atlas.ttp.demo.ui.theme.AtlasPrimary

/**
 * Product catalog screen displaying a grid of available products.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CatalogScreen(
    cartItemCount: Int,
    onAddToCart: (Product) -> Unit,
    onViewCart: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "Atlas Coffee Shop",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Tap to add items",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                actions = {
                    // Cart button with badge
                    BadgedBox(
                        badge = {
                            if (cartItemCount > 0) {
                                Badge(
                                    containerColor = MaterialTheme.colorScheme.error
                                ) {
                                    Text(cartItemCount.toString())
                                }
                            }
                        }
                    ) {
                        IconButton(onClick = onViewCart) {
                            Icon(
                                imageVector = Icons.Default.ShoppingCart,
                                contentDescription = "View Cart",
                                tint = AtlasPrimary
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            if (cartItemCount > 0) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shadowElevation = 8.dp
                ) {
                    Button(
                        onClick = onViewCart,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = AtlasPrimary
                        )
                    ) {
                        Icon(
                            imageVector = Icons.Default.ShoppingCart,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("View Cart ($cartItemCount items)")
                    }
                }
            }
        }
    ) { paddingValues ->
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Coffee section
            item(span = { GridItemSpan(2) }) {
                SectionHeader(title = "Coffee")
            }
            items(SampleProducts.coffeeProducts) { product ->
                ProductCard(
                    product = product,
                    onAddToCart = onAddToCart
                )
            }

            // Tea section
            item(span = { GridItemSpan(2) }) {
                SectionHeader(title = "Tea")
            }
            items(SampleProducts.teaProducts) { product ->
                ProductCard(
                    product = product,
                    onAddToCart = onAddToCart
                )
            }

            // Pastries section
            item(span = { GridItemSpan(2) }) {
                SectionHeader(title = "Pastries")
            }
            items(SampleProducts.pastryProducts) { product ->
                ProductCard(
                    product = product,
                    onAddToCart = onAddToCart
                )
            }

            // Sandwiches section
            item(span = { GridItemSpan(2) }) {
                SectionHeader(title = "Sandwiches")
            }
            items(SampleProducts.sandwichProducts) { product ->
                ProductCard(
                    product = product,
                    onAddToCart = onAddToCart
                )
            }

            // Bottom padding for FAB
            item(span = { GridItemSpan(2) }) {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }
}

@Composable
private fun SectionHeader(
    title: String,
    modifier: Modifier = Modifier
) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        color = AtlasPrimary,
        modifier = modifier.padding(top = 8.dp, bottom = 4.dp)
    )
}
