define(function (require, exports, module) {

	"use strict";

	var CommandManager = brackets.getModule('command/CommandManager'),
		Menus = brackets.getModule('command/Menus'),
		EditorManager = brackets.getModule('editor/EditorManager'),
		DocumentManager = brackets.getModule("document/DocumentManager"),
		PreferencesManager = brackets.getModule("preferences/PreferencesManager"),
		OneLiner = require('one-liner'),
		CONTEXTUAL_COMMAND_ID = "caferati.oneliner",
		menu,
		command,
		contextMenu;

	function reindent(codeMirror, from, to) {
		codeMirror.operation(function () {
			codeMirror.eachLine(from, to, function (line) {
				codeMirror.indentLine(line.lineNo(), "smart");
			});
		});
	}

	function run() {
		var editor = EditorManager.getCurrentFullEditor(),
			selectedText = editor.getSelectedText(),
			selection = editor.getSelection(),
			doc = DocumentManager.getCurrentDocument(),
			codeMirror = editor._codeMirror,
			text;
		if (!selectedText.length) return false;
		text = OneLiner.run(selectedText);
		codeMirror.replaceRange(text, selection.start, selection.end);
		codeMirror.setSelection(selection.start, {
			ch: text.length + 1,
			line: selection.start.line
		});
		reindent(codeMirror, selection.start.line, selection.start.line * 1 + (text.match(/\n/mig) ? text.match(/[\n\r]/mig).length : 0) + 1);		
	}

	CommandManager.register("One Liner", CONTEXTUAL_COMMAND_ID, run);

	menu = Menus.getMenu(Menus.AppMenuBar.EDIT_MENU);
	command = [{
		key: "Ctrl-Shift-T",
		platform: "win"
    }, {
		key: "Cmd-Shift-T",
		platform: "mac"
    }];

	menu.addMenuDivider();
	menu.addMenuItem(CONTEXTUAL_COMMAND_ID, command);
	contextMenu = Menus.getContextMenu(Menus.ContextMenuIds.EDITOR_MENU);
	contextMenu.addMenuItem(CONTEXTUAL_COMMAND_ID);
});
