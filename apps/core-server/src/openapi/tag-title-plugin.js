(function () {
  // Replaces UI tag titles with "x-displayName" extension if specified
  window.TagTitlePlugin = function () {
    return {
      wrapComponents: {
        OperationTag: function (Orig, system) {
          return function (props) {
            var originalEl = system.React.createElement(Orig, props);

            try {
              var tag = props.tag;
              var tagObj = props.tagObj;
              var tagDetails =
                tagObj && tagObj.get ? tagObj.get("tagDetails") : null;
              var displayName =
                tagDetails && tagDetails.get
                  ? tagDetails.get("x-displayName")
                  : null;

              if (tag && displayName) {
                requestAnimationFrame(function () {
                  try {
                    var targetBlock = document.querySelector(
                      `h3.opblock-tag[data-tag="${tag}"]`,
                    );
                    if (!targetBlock) {
                      return;
                    }

                    var label = targetBlock.querySelector(
                      `a[href="#/${tag}"] span`,
                    );
                    if (!label) {
                      return;
                    }

                    label.textContent = displayName;
                  } catch (_e) {}
                });
              }
            } catch (_e) {}

            return originalEl;
          };
        },
      },
    };
  };

  var orig = window.SwaggerUIBundle;
  if (typeof orig === "function" && !orig.__tagTitlePatched) {
    var wrapped = function (opts) {
      opts = opts || {};
      opts.plugins = (opts.plugins || []).concat([window.TagTitlePlugin]);
      return orig(opts);
    };

    for (var k in orig) {
      try {
        wrapped[k] = orig[k];
      } catch (e) {}
    }

    try {
      wrapped.presets = orig.presets;
    } catch (e) {}
    try {
      wrapped.plugins = orig.plugins;
    } catch (e) {}

    wrapped.__tagTitlePatched = true;
    window.SwaggerUIBundle = wrapped;
  }
})();
