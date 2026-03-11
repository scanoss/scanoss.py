# Copyright (c) 2024 The R Foundation for Statistical Computing
#
# This file is part of R, which is free software. You can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# R is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.

library(ggplot2)
library(dplyr)
library(tidyr)
require(stats)

#' Perform statistical analysis on the given dataset
#'
#' @param data A data frame containing the input data
#' @param target_col The name of the target variable column
#' @param predictor_cols A character vector of predictor column names
#' @return A list containing model summary and diagnostics
analyze_regression <- function(data, target_col, predictor_cols) {
  if (!is.data.frame(data)) {
    stop("Input must be a data frame")
  }

  formula_str <- paste(target_col, "~", paste(predictor_cols, collapse = " + "))
  model <- lm(as.formula(formula_str), data = data)

  residuals <- residuals(model)
  fitted_vals <- fitted(model)

  diagnostics <- list(
    shapiro_test = shapiro.test(residuals),
    r_squared = summary(model)$r.squared,
    adj_r_squared = summary(model)$adj.r.squared,
    f_statistic = summary(model)$fstatistic
  )

  result <- list(
    model = model,
    summary = summary(model),
    diagnostics = diagnostics
  )

  return(result)
}

plot_diagnostics <- function(model, output_dir = "plots") {
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }

  residual_data <- data.frame(
    fitted = fitted(model),
    residuals = residuals(model),
    standardized = rstandard(model)
  )

  p1 <- ggplot(residual_data, aes(x = fitted, y = residuals)) +
    geom_point(alpha = 0.5) +
    geom_hline(yintercept = 0, linetype = "dashed", color = "red") +
    labs(title = "Residuals vs Fitted", x = "Fitted Values", y = "Residuals") +
    theme_minimal()

  ggsave(file.path(output_dir, "residuals_vs_fitted.png"), p1)

  p2 <- ggplot(residual_data, aes(sample = standardized)) +
    stat_qq() +
    stat_qq_line(color = "red") +
    labs(title = "Normal Q-Q Plot") +
    theme_minimal()

  ggsave(file.path(output_dir, "qq_plot.png"), p2)

  invisible(list(p1, p2))
}