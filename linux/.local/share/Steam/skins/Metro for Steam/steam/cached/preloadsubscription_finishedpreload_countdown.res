"steam/cached/PreloadSubscription_FinishedPreload_Countdown.res"
{
	"PreDownloadDialog"
	{
		"ControlName"		"CPreloadAppDialog"
		"fieldName"		"PreDownloadDialog"
		"xpos"		"780"
		"ypos"		"392"
		"wide"		"360"
		"tall"		"366"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"settitlebarvisible"		"1"
		"title"		"#Steam_PreloadComplete_Title"
	}
	"PreloadProgress"
	{
		"ControlName"		"ProgressBar"
		"fieldName"		"PreloadProgress"
		"xpos"		"28"
		"ypos"		"104"
		"wide"		"300"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"0"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"progress"		"1.000000"
	}
	"CancelButton"
	{
		"ControlName"		"Button"
		"fieldName"		"CancelButton"
		"xpos"		"0"
		"ypos"		"0"
		"wide"		"64"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"0"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"textAlignment"		"west"
		"wrap"		"0"
		"Default"		"0"
	}
	"PauseButton"
	{
		"ControlName"		"Button"
		"fieldName"		"PauseButton"
		"xpos"		"0"
		"ypos"		"0"
		"wide"		"64"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"0"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_PreloadPause"
		"textAlignment"		"west"
		"wrap"		"0"
		"Command"		"PausePreloading"
		"Default"		"0"
	}
	"PreloadInfo"
	{
		"ControlName"		"Label"
		"fieldName"		"PreloadInfo"
		"xpos"		"28"
		"ypos"		"100"
		"wide"		"300"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"0"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_PreloadProgress"
		"textAlignment"		"west"
		"wrap"		"0"
	}
	"Label1"
	{
		"ControlName"		"Label"
		"fieldName"		"Label1"
		"xpos"		"28"
		"ypos"		"54"
		"wide"		"300"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_PreloadGameName"
		"textAlignment"		"west"
		"font"		"UiHeadline"
		"wrap"		"0"
	}
	"Label2"
	{
		"ControlName"		"Label"
		"fieldName"		"Label2"
		"xpos"		"28"
		"ypos"		"76"
		"wide"		"300"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_PreloadComplete"
		"textAlignment"		"west"
		"wrap"		"0"
	}
	"Button2"
	{
		"ControlName"		"Button"
		"fieldName"		"Button2"
		"xpos"		"266"
		"ypos"		"324"
		"wide"		"74"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"1"
		"paintbackground"		"1"
		"labelText"		"#vgui_close"
		"textAlignment"		"west"
		"wrap"		"0"
		"Command"		"Close"
		"Default"		"1"
	}
	"LaunchGameButton"
	{
		"ControlName"		"Button"
		"fieldName"		"LaunchGameButton"
		"xpos"		"181"
		"ypos"		"224"
		"wide"		"142"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"0"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_LaunchGame"
		"textAlignment"		"west"
		"wrap"		"0"
		"Command"		"LaunchGame"
		"Default"		"0"
	}
	"DaysDigits"
	{
		"ControlName"		"Label"
		"fieldName"		"DaysDigits"
		"xpos"		"44"
		"ypos"		"140"
		"wide"		"60"
		"tall"		"52"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"%days%"
		"textAlignment"		"center"
		"font"		"CountdownNumbers"
		"wrap"		"0"
	}
	"HoursDigits"
	{
		"ControlName"		"Label"
		"fieldName"		"HoursDigits"
		"xpos"		"112"
		"ypos"		"140"
		"wide"		"60"
		"tall"		"52"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"%hours%"
		"textAlignment"		"center"
		"font"		"CountdownNumbers"
		"wrap"		"0"
	}
	"MinutesDigits"
	{
		"ControlName"		"Label"
		"fieldName"		"MinutesDigits"
		"xpos"		"180"
		"ypos"		"140"
		"wide"		"60"
		"tall"		"52"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"%minutes%"
		"textAlignment"		"center"
		"font"		"CountdownNumbers"
		"wrap"		"0"
	}
	"SecondsDigits"
	{
		"ControlName"		"Label"
		"fieldName"		"SecondsDigits"
		"xpos"		"249"
		"ypos"		"140"
		"wide"		"60"
		"tall"		"52"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"%seconds%"
		"textAlignment"		"center"
		"font"		"CountdownNumbers"
		"wrap"		"0"
	}
	"DaysLabel"
	{
		"ControlName"		"Label"
		"fieldName"		"DaysLabel"
		"xpos"		"40"
		"ypos"		"182"
		"wide"		"70"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_Countdown_Days"
		"textAlignment"		"center"
		"wrap"		"0"
	}
	"HoursLabel"
	{
		"ControlName"		"Label"
		"fieldName"		"HoursLabel"
		"xpos"		"109"
		"ypos"		"182"
		"wide"		"70"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_Countdown_Hours"
		"textAlignment"		"center"
		"wrap"		"0"
	}
	"MinutesLabel"
	{
		"ControlName"		"Label"
		"fieldName"		"MinutesLabel"
		"xpos"		"176"
		"ypos"		"182"
		"wide"		"70"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_Countdown_Minutes"
		"textAlignment"		"center"
		"wrap"		"0"
	}
	"SecondsLabel"
	{
		"ControlName"		"Label"
		"fieldName"		"SecondsLabel"
		"xpos"		"245"
		"ypos"		"182"
		"wide"		"70"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_Countdown_Seconds"
		"textAlignment"		"center"
		"wrap"		"0"
	}
	"PreloadCountdownText1"
	{
		"ControlName"		"Label"
		"fieldName"		"PreloadCountdownText1"
		"xpos"		"28"
		"ypos"		"110"
		"wide"		"312"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_DoDFreeWeekend_BeginsIn"
		"textAlignment"		"west"
		"wrap"		"0"
	}
	"PreloadCountdownText2"
	{
		"ControlName"		"Label"
		"fieldName"		"PreloadCountdownText2"
		"xpos"		"28"
		"ypos"		"257"
		"wide"		"300"
		"tall"		"40"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_DoDFreeWeekend_Info"
		"textAlignment"		"north-west"
		"wrap"		"1"
	}
	"PreloadCountdownText3"
	{
		"ControlName"		"URLLabel"
		"fieldName"		"PreloadCountdownText3"
		"xpos"		"28"
		"ypos"		"297"
		"wide"		"310"
		"tall"		"24"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"labelText"		"#Steam_DoDFreeWeekend_URL"
		"textAlignment"		"west"
		"wrap"		"0"
		"URLText"		"http://www.steampowered.com/status"
	}
	"CountdownBackground"
	{
		"ControlName"		"ImagePanel"
		"fieldName"		"CountdownBackground"
		"xpos"		"34"
		"ypos"		"136"
		"zpos"		"-1"
		"wide"		"296"
		"tall"		"84"
		"AutoResize"		"0"
		"PinCorner"		"0"
		"visible"		"1"
		"enabled"		"1"
		"tabPosition"		"0"
		"paintbackground"		"1"
		"image"		"resource/borders/CountdownBG"
		"gradientVertical"		"0"
		"scaleImage"		"0"
	}
	layout
	{
		place { control="frame_minimize,frame_maximize,frame_close" align=right width=34 height=27 }
		region { name="bottom" align=bottom height=44 margin=8 }
		place { control="Button2" region=bottom align=right width=84 height=28 spacing=8 }
	}
}
