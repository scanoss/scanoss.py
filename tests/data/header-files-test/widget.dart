// Copyright 2014 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:flutter/foundation.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/widgets.dart';

/// A material design card widget.
///
/// A card is a sheet of material used to represent some related information,
/// for example an album, a geographical location, a meal, contact details, etc.
class MaterialCard extends StatelessWidget {
  const MaterialCard({
    super.key,
    this.color,
    this.elevation = 1.0,
    this.shape,
    this.borderOnForeground = true,
    this.margin,
    this.clipBehavior = Clip.none,
    this.child,
  });

  final Color? color;
  final double elevation;
  final ShapeBorder? shape;
  final bool borderOnForeground;
  final EdgeInsetsGeometry? margin;
  final Clip clipBehavior;
  final Widget? child;

  @override
  Widget build(BuildContext context) {
    final CardThemeData cardTheme = CardTheme.of(context);
    final CardThemeData defaults = _CardDefaults(context);

    return Semantics(
      container: true,
      child: Container(
        margin: margin ?? cardTheme.margin ?? defaults.margin,
        child: Material(
          type: MaterialType.card,
          color: color ?? cardTheme.color ?? defaults.color,
          elevation: elevation,
          shape: shape ?? cardTheme.shape ?? defaults.shape,
          borderOnForeground: borderOnForeground,
          clipBehavior: clipBehavior,
          child: Semantics(
            explicitChildNodes: true,
            child: child,
          ),
        ),
      ),
    );
  }
}

class _CardDefaults extends CardThemeData {
  _CardDefaults(this.context);

  final BuildContext context;

  @override
  Color? get color => Theme.of(context).cardColor;

  @override
  double? get elevation => 1.0;

  @override
  EdgeInsetsGeometry? get margin => const EdgeInsets.all(4.0);

  @override
  ShapeBorder? get shape => const RoundedRectangleBorder(
    borderRadius: BorderRadius.all(Radius.circular(12.0)),
  );
}