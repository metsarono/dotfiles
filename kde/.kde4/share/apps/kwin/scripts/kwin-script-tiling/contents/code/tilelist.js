/********************************************************************
 KWin - the KDE window manager
 This file is part of the KDE project.

Copyright (C) 2012 Mathias Gottschlag <mgottschlag@gmail.com>
Copyright (C) 2013-2014 Fabian Homborg <FHomborg@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*********************************************************************/

/**
 * Class which keeps track of all tiles in the system. The class automatically
 * puts tab groups in one single tile. Tracking of new and removed clients is
 * done here as well.
 * @class
 */
function TileList() {
    /**
     * List of currently existing tiles.
     */
    this.tiles = [];
    /**
     * Signal which is triggered whenever a new tile is added to the list.
     */
    this.tileAdded = new Signal();
    /**
     * Signal which is triggered whenever a tile is removed from the list.
     */
    this.tileRemoved = new Signal();

	try {
		this.noBorder = readConfig("noBorder", false);
	} catch(err) {
		print(err, "in TileList");
	}

    // We connect to the global workspace callbacks which are triggered when
    // clients are added in order to be able to keep track of the
    // new tiles
	// Do not use clientRemoved as it is called after FFM selects a new active client
	// Instead, connect to client.windowClosed
    var self = this;
    workspace.clientAdded.connect(function(client) {
		// Don't connect signal if the client is ignored
		if (TileList._isIgnored(client)) {
			client.tiling_tileIndex = -1;
			client.keepBelow = false;
			return;
		}
		
		// Delay adding until the window is actually shown
		// This prevents (some, but not all) graphics bugs
		// due to resizing before the pixmap is created (or something like that)
		// Unfortunately, this signal is only emitted when compositing
		// FIXME: options.useCompositing (et al) never change from the initial value
		// and the changed signals aren't fired
		if (options.useCompositing == true) {
			client.windowShown.connect(function() {
				self._onClientAdded(client);
			});
		} else {
			self._onClientAdded(client);
		}
    });
    workspace.clientMaximizeSet.connect(function(client, h, v) {
		var tile = self.getTile(client);
		if (tile != null) {
			tile.onClientMaximizedStateChanged(client, h, v);
		}
	});
};

/*
 * Connect all signals for a client we need
 */
TileList.prototype.connectSignals = function(client) {
	if (TileList._isIgnored(client)) {
		return;
	}

    var self = this;

	if (client.tiling_connected1 != true) {
		// First handle fullscreen and shade as they can change and affect the tiling or floating decision
		client.fullScreenChanged.connect(function() {
			if (client.fullScreen == true) {
				client.tiling_floating = true;
				client.keepBelow = false;
			} else {
				client.keepBelow = true;
				self._onClientAdded(client);
			}
		});
		client.shadeChanged.connect(function() {
			if (client.shade == true) {
				client.tiling_floating = true;
				self._onClientRemoved(client);
			} else {
				self.addClient(client);
			}
		});
		client.tiling_connected1 = true;
	}
	if (client.tiling_connected2 == true) {
		return;
	}
    client.tabGroupChanged.connect(function() {
        self._onClientTabGroupChanged(client);
    });
    // We also have to connect other client signals here instead of in Tile
    // because the tile of a client might change over time
    var getTile = function(client) {
        return self.getTile(client);
    };
	// geometryChanged fires also on maximizedStateChanged and stepUserMovedResized
	// so use geometryShapeChanged
    client.geometryShapeChanged.connect(function() {
		var tile = getTile(client);
		if (tile != null) {
			tile.onClientGeometryChanged(client);
		}
    });
	client.windowClosed.connect(function(cl, deleted) {
		self._onClientRemoved(client);
	});
    client.clientStartUserMovedResized.connect(function() {
		var tile = getTile(client);
		if (tile != null) {
			tile.onClientStartUserMovedResized(client);
		}
    });
    client.clientStepUserMovedResized.connect(function() {
		var tile = getTile(client);
		if (tile != null) {
			tile.onClientStepUserMovedResized(client);
		}
    });
    client.clientFinishUserMovedResized.connect(function() {
		var tile = getTile(client);
		if (tile != null) {
			tile.onClientFinishUserMovedResized(client);
		}
    });
    client.desktopChanged.connect(function() {
		var tile = getTile(client);
		if (tile != null) {
			tile.onClientDesktopChanged(client);
		}
	});
	client.clientMinimized.connect(function(client) {
		try {
			self._onClientRemoved(client);
		} catch(err) {
			print(err, "in mimimized");
		}
	});
	client.clientUnminimized.connect(function(client) {
		try {
			self._onClientAdded(client);
		} catch(err) {
			print(err, "in Unminimized");
		}
	});
	client.tiling_connected2 = true;
};
	
/**
 * Adds another client to the tile list. When this is called, the tile list also
 * adds callback functions to the relevant client signals to trigger tile change
 * events when necessary. This function might trigger a tileAdded event.
 *
 * @param client Client which is added to the tile list.
 */
TileList.prototype.addClient = function(client) {
	if (client == null) {
		return;
	}
    if (TileList._isIgnored(client)) {
		client.tiling_tileIndex = -1;
		client.keepBelow = false;
		// WARNING: This crashes kwin!
		//client.tiling_floating = true;
        return;
    }

	if (this.noBorder == true) {
		client.noBorder = true;
	}

	// Check whether the client is part of an existing tile
	if (this._indexWithClient(client) != -1) {
		return;
	}

	this.connectSignals(client);

	// shade can't be activated without borders, so it's okay to handle it here
	if (client.fullScreen == true || client.shade == true) {
		client.keepBelow = false;
		return;
	}

	client.keepBelow = true;

	// If the client isn't the current tab, it's added to a tabgroup
	// (because of autogrouping)
	// HACK: Find it by comparing rectangles (yes, really)
	if (client.isCurrentTab == false) {
		for (var i = 0; i < this.tiles.length; i++) {
			if (util.compareRect(this.tiles[i].rectangle, client.geometry) == true) {
				if (this.tiles[i]._currentDesktop == client.desktop &&
					this.tiles[i]._currentScreen  == client.screen) {
					this.tiles[i].addClient(client);
					break;
				}
			}
		}
	} else {
		this._addTile(client);
	}
	client.tiling_floating = false;
};

/**
 * Returns the tile in which a certain client is located.
 *
 * @param client Client for which the tile shall be returned.
 * @return Tile in which the client is located.
 */
TileList.prototype.getTile = function(client) {
	var index = this._indexWithClient(client);
	if (index > -1) {
		return this.tiles[index];
	}
	return null;
};

TileList.prototype._onClientAdded = function(client) {
    this.addClient(client);
};

TileList.prototype._onClientRemoved = function(client) {
	try {
		// Unset keepBelow because we set it when tiling
		client.keepBelow = false;

		// Remove the client from its tile
		var tileIndex = this._indexWithClient(client);
		var tile = this.tiles[tileIndex];
		if (tile != null) {
			if (tile.clients.length == 1) {
				// Remove the tile if this was the last client in it
				this._removeTile(tileIndex);
			} else {
				// Remove the client from its tile
				tile.removeClient(client);
			}
		}
		// Don't remove tileIndex, so we can move the window to its position in case it comes back (after minimize etc)
		//client.tiling_tileIndex = - 1;
		if (client.tiling_floating == true) {
			client.noBorder = false;
		}
	} catch(err) {
		print(err, "in onClientRemoved with", client.resourceClass.toString());
	}
};

TileList.prototype._onClientTabGroupChanged = function(client) {
	try {
		// FIXME: This is a huge kludge as kwin doesn't actually export the tabgroup
		// For starters, this only works because we ignore geometryChanged for clients that aren't the current tab
		var index = this._indexWithClient(client);
		if (client.isCurrentTab == false) {
			var tabGroup = null;
			for (var i = 0; i < this.tiles.length; i++) {
				// We don't set geometry if the client isn't currentTab, so find its tabgroup by place
				var rect  = this.tiles[i].rectangle;
				if (util.compareRect(rect, client.geometry) == true) {
					// TODO: Is this necessary or is desktopChanged always called before tabgroupchanged?
					if (this.tiles[i]._currentDesktop == client.desktop || client.desktop == -1) {
						tabGroup = this.tiles[i];
						break;
					}
				}
			}
			if (index > -1) {
				this.tiles[index].removeClient(client);
				if (this.tiles[index].clients.length < 1) {
					this._removeTile(index);
				}
			}
			if (tabGroup != this.tiles[index]) {
				tabGroup.addClient(client);
			} else {
				tabGroup.removeClient(client);
				if (tabGroup.clients.length < 1) {
					this._removeTile(this.tiles.indexOf(tabGroup));
				}
			}
		} else {
			if (index > -1) {
				if (this.tiles[index].clients.length > 1) {
					this.tiles[index].removeClient(client);
					this.addClient(client);
				}
			}
		}
	} catch(err) {
		print(err, "in TileList._onClientTabGroupChanged");
	}
};

TileList.prototype._addTile = function(client) {
	var tileIndex = -1;
	if (client.tiling_tileIndex > -1) {
		tileIndex = client.tiling_tileIndex;
	}
	var newTile = new Tile(client, tileIndex);
    this.tiles.push(newTile);
    this.tileAdded.emit(newTile);
};

TileList.prototype._removeTile = function(tileIndex) {
	try {
		// Don't modify tileIndex here - this is a list of _all_ tiles, while tileIndex is the index on the desktop
		var tile = this.tiles[tileIndex];
		if (tileIndex > -1) {
			this.tiles.splice(tileIndex, 1);
		}
		this.tileRemoved.emit(tile);
	} catch(err) {
		print(err, "in TileList._removeTile");
	}
};

/**
 * Returns true for clients which shall never be handled by the tiling script,
 * e.g. panels, dialogs or the user-defined apps
 */
TileList._isIgnored = function(client) {
	// TODO: Add regex and more options (by title/caption, override a floater, maybe even a complete scripting language / code)
    // Application workarounds should be put here
	// HACK: Qt gives us a method-less QVariant(QStringList) if we ask for an array
	// Ask for a string instead (which can and should still be a StringList for the UI)
	var fl = "yakuake,krunner,plasma,plasma-desktop,plugin-container,Wine,klipper";
	// TODO: This could break if an entry contains whitespace or a comma - it needs to be validated on the qt side
	var floaters = String(readConfig("floaters", fl)).replace(/ /g,"").split(",");
	if (floaters.indexOf(client.resourceClass.toString()) > -1) {
		client.syncTabGroupFor("kwin_tiling_floats", true);
		return true;
	}
	// HACK: Steam doesn't set the windowtype properly
	// Everything that isn't captioned "Steam" should be a dialog - these resize worse than the main window does
	// With the exception of course of the class-less update/start dialog with the caption "Steam" (*Sigh*)
	if (client.resourceClass.toString() == "steam" && client.caption != "Steam") {
		return true;
	} else if (client.resourceClass.toString() != "steam" && client.caption == "Steam") {
		return true;
	}
	if (client.specialWindow == true) {
		return true;
	}
	if (client.desktopWindow == true) {
		return true;
	}
	if (client.dock == true) {
		return true;
	}
	if (client.toolbar == true) {
		return true;
	}
	if (client.menu == true) {
		return true;
	}
	if (client.dialog == true) {
		return true;
	}
	if (client.splash == true) {
		return true;
	}
	if (client.utility == true) {
		return true;
	}
	if (client.dropdownMenu == true) {
		return true;
	}
	if (client.popupMenu == true) {
		return true;
	}
	if (client.tooltip == true) {
		return true;
	}
	if (client.notification == true) {
		return true;
	}
	if (client.comboBox == true) {
		return true;
	}
	if (client.dndIcon == true) {
		return true;
	}

    return false;
};

TileList.prototype._indexWithClient = function(client) {
	for (var i = 0; i < this.tiles.length; i++) {
		if (this.tiles[i].hasClient(client)) {
			return i;
		}
	}
	return -1;
};

/*
 * Set the border for all non-floating managed clients
 * This is "noBorder" (i.e. inverted boolean) since that's what kwin uses
*/
TileList.prototype.setNoBorder = function(nB) {
	this.noBorder = nB;
	this.tiles.forEach(function (t) {
		for (var i = 0; i < t.clients.length; i++) {
			if (t.clients[i].tiling_floating != true) {
				t.clients[i].noBorder = nB;
			}
		}
	});
};

TileList.prototype.toggleNoBorder = function() {
	try {
		this.setNoBorder(!this.noBorder);
	} catch (err) {
		print(err, "in TileList.toggleNoBorder");
	}
};
