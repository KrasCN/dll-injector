package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// GreenHackerTheme is a hacker-style theme with black background and green text
type GreenHackerTheme struct{}

// Ensure GreenHackerTheme implements fyne.Theme interface
var _ fyne.Theme = (*GreenHackerTheme)(nil)

// Color constants
var (
	// Primary colors
	colorPrimary   = color.NRGBA{R: 0, G: 240, B: 0, A: 255}   // Bright green
	colorSecondary = color.NRGBA{R: 0, G: 200, B: 0, A: 255}   // Medium green
	colorAccent    = color.NRGBA{R: 0, G: 255, B: 128, A: 255} // Light green

	// Background colors
	colorBackground      = color.NRGBA{R: 0, G: 0, B: 0, A: 255}    // Pure black
	colorBackgroundDark  = color.NRGBA{R: 15, G: 15, B: 15, A: 255} // Very dark gray
	colorCardBackground  = color.NRGBA{R: 20, G: 20, B: 20, A: 255} // Dark gray
	colorInputBackground = color.NRGBA{R: 10, G: 10, B: 10, A: 255} // Almost black

	// Text colors
	colorText        = color.NRGBA{R: 0, G: 240, B: 0, A: 255}   // Bright green
	colorTextMuted   = color.NRGBA{R: 0, G: 180, B: 0, A: 255}   // Medium green
	colorTextInvert  = color.NRGBA{R: 0, G: 255, B: 128, A: 255} // Light green
	colorPlaceholder = color.NRGBA{R: 0, G: 150, B: 0, A: 255}   // Dark green

	// Status colors
	colorSuccess = color.NRGBA{R: 0, G: 255, B: 0, A: 255}   // Bright green
	colorWarning = color.NRGBA{R: 255, G: 255, B: 0, A: 255} // Yellow
	colorError   = color.NRGBA{R: 255, G: 0, B: 0, A: 255}   // Red
	colorInfo    = color.NRGBA{R: 0, G: 255, B: 255, A: 255} // Cyan
)

// Color returns the theme color for the specified name
func (m GreenHackerTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Always use dark variant colors for our hacker theme
	switch name {
	case theme.ColorNameBackground:
		return colorBackground
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNamePrimary:
		return colorPrimary
	case theme.ColorNameFocus:
		return colorAccent
	case theme.ColorNameButton:
		return colorCardBackground
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0, G: 100, B: 0, A: 255}
	case theme.ColorNamePlaceHolder:
		return colorPlaceholder
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0, G: 160, B: 0, A: 255}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 180}
	case theme.ColorNameInputBackground:
		return colorInputBackground
	case theme.ColorNameHover:
		return color.NRGBA{R: 10, G: 80, B: 10, A: 255}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0, G: 120, B: 0, A: 127}
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 230}
	}

	return theme.DefaultTheme().Color(name, variant)
}

// Font returns the font for the specified text style
func (m GreenHackerTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns the theme icon for the specified name
func (m GreenHackerTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns the theme size for the specified name
func (m GreenHackerTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameScrollBar:
		return 6
	case theme.SizeNameScrollBarSmall:
		return 4
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 18
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 4
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInlineIcon:
		return 20
	}

	return theme.DefaultTheme().Size(name)
}

// NewModernTheme creates a new modern light theme
func NewModernTheme() fyne.Theme {
	return &GreenHackerTheme{}
}
