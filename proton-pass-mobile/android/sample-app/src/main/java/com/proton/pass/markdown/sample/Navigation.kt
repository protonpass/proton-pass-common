package com.proton.pass.markdown.sample

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.proton.pass.markdown.sample.ui.screens.EditScreen
import com.proton.pass.markdown.sample.ui.screens.ViewScreen

/**
 * Navigation routes
 */
sealed class Screen(val route: String) {
    data object View : Screen("view")
    data object Edit : Screen("edit")
}

/**
 * Main navigation host for the app
 */
@Composable
fun AppNavigation(viewModel: MarkdownViewModel = viewModel()) {
    val navController = rememberNavController()

    NavHost(
        navController = navController,
        startDestination = Screen.View.route
    ) {
        composable(Screen.View.route) {
            ViewScreen(
                viewModel = viewModel,
                onEdit = {
                    navController.navigate(Screen.Edit.route)
                }
            )
        }

        composable(Screen.Edit.route) {
            EditScreen(
                viewModel = viewModel,
                onBack = {
                    navController.popBackStack()
                }
            )
        }
    }
}
