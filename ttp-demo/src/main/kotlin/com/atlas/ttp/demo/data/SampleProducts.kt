package com.atlas.ttp.demo.data

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*

/**
 * Sample product catalog for the demo app.
 */
object SampleProducts {

    val coffeeProducts = listOf(
        Product(
            id = "espresso",
            name = "Espresso",
            description = "Rich and bold single shot",
            priceInCents = 325,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        ),
        Product(
            id = "americano",
            name = "Americano",
            description = "Espresso with hot water",
            priceInCents = 375,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        ),
        Product(
            id = "latte",
            name = "Caffe Latte",
            description = "Espresso with steamed milk",
            priceInCents = 495,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        ),
        Product(
            id = "cappuccino",
            name = "Cappuccino",
            description = "Espresso with foam",
            priceInCents = 475,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        ),
        Product(
            id = "mocha",
            name = "Caffe Mocha",
            description = "Espresso with chocolate",
            priceInCents = 550,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        ),
        Product(
            id = "cold_brew",
            name = "Cold Brew",
            description = "Smooth cold-steeped coffee",
            priceInCents = 450,
            category = ProductCategory.COFFEE,
            icon = Icons.Default.Coffee
        )
    )

    val teaProducts = listOf(
        Product(
            id = "green_tea",
            name = "Green Tea",
            description = "Japanese sencha",
            priceInCents = 350,
            category = ProductCategory.TEA,
            icon = Icons.Default.Spa
        ),
        Product(
            id = "chai_latte",
            name = "Chai Latte",
            description = "Spiced tea with milk",
            priceInCents = 475,
            category = ProductCategory.TEA,
            icon = Icons.Default.Spa
        ),
        Product(
            id = "earl_grey",
            name = "Earl Grey",
            description = "Classic bergamot tea",
            priceInCents = 325,
            category = ProductCategory.TEA,
            icon = Icons.Default.Spa
        )
    )

    val pastryProducts = listOf(
        Product(
            id = "croissant",
            name = "Butter Croissant",
            description = "Flaky French pastry",
            priceInCents = 395,
            category = ProductCategory.PASTRY,
            icon = Icons.Default.BakeryDining
        ),
        Product(
            id = "muffin",
            name = "Blueberry Muffin",
            description = "Fresh-baked with berries",
            priceInCents = 375,
            category = ProductCategory.PASTRY,
            icon = Icons.Default.BakeryDining
        ),
        Product(
            id = "scone",
            name = "Cranberry Scone",
            description = "Classic British treat",
            priceInCents = 350,
            category = ProductCategory.PASTRY,
            icon = Icons.Default.BakeryDining
        ),
        Product(
            id = "cookie",
            name = "Chocolate Chip Cookie",
            description = "Warm and gooey",
            priceInCents = 295,
            category = ProductCategory.PASTRY,
            icon = Icons.Default.Cookie
        )
    )

    val sandwichProducts = listOf(
        Product(
            id = "avocado_toast",
            name = "Avocado Toast",
            description = "Sourdough with avocado",
            priceInCents = 850,
            category = ProductCategory.SANDWICH,
            icon = Icons.Default.LunchDining
        ),
        Product(
            id = "turkey_sandwich",
            name = "Turkey Club",
            description = "Turkey, bacon, lettuce",
            priceInCents = 995,
            category = ProductCategory.SANDWICH,
            icon = Icons.Default.LunchDining
        ),
        Product(
            id = "veggie_wrap",
            name = "Veggie Wrap",
            description = "Fresh vegetables in tortilla",
            priceInCents = 875,
            category = ProductCategory.SANDWICH,
            icon = Icons.Default.LunchDining
        )
    )

    val allProducts: List<Product> = coffeeProducts + teaProducts + pastryProducts + sandwichProducts

    fun getProductById(id: String): Product? = allProducts.find { it.id == id }
}
