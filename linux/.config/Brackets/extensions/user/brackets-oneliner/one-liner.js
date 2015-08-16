define(function (require, exports, module) {

	function hasOneLine(text) {
		return text.match(/([\n\r])/ig) ? false : true;
	}

	function oneLine(text) {
		return text
			.replace(/(\r\n|\n|\r)/mig, "")
			.replace(/([\s]+)/mig, " ")
			.replace(/([\t]+)/mig, " ")
			.trim();
	}

	function trim(text) {
		// testa se tem html, se tem html da um trim antes;
		var original = text;
		if(text.match(/<\/?([^>]*)>/mig)){
			text = text.replace(/(>)([\s\t\r\n]*)(<)/mig,"$1$3");
		}
		if(text.length == original.length){
			text = text.replace(/([\s]+)/gm, "").replace(/([\t]+)/gm, "")
		}
		return text
	}

	function run(text) {
		return hasOneLine(text) ? trim(text) : oneLine(text);
	}

	return {
		run: run
	};

});
