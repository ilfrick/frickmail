/* Copyright © 2011-2015 by Neil Jenkins. MIT Licensed. */
/* eslint max-len: 0 */

/**
  TODO: modifyBlocks function doesn't work very good.
  For example you have: UL > LI > [cursor here in text]
  Then create blockquote at cursor, the result is: BLOCKQUOTE > UL > LI
  not UL > LI > BLOCKQUOTE
*/

(() => {
  // source/node/TreeIterator.ts
  var SHOW_ELEMENT = 1;
  var SHOW_TEXT = 4;
  var SHOW_ELEMENT_OR_TEXT = 5;
  var filterAccept = NodeFilter.FILTER_ACCEPT;
  TreeWalker.prototype.previousPONode = function() {
    let current = this.currentNode;
    let node = current.lastChild;
    while (!node && current) {
      if (current === this.root) {
        break;
      }
      node = this.previousSibling();
      if (!node) {
        current = this.parentNode();
      }
    }
    node && (this.currentNode = node);
    return node;
  };
  var createTreeWalker = (root, whatToShow, filter) => document.createTreeWalker(root, whatToShow, filter ? {
    acceptNode: (node) => filter(node) ? filterAccept : NodeFilter.FILTER_SKIP
  } : null);

  // source/Constants.ts
  var ELEMENT_NODE = 1;
  var TEXT_NODE = 3;
  var DOCUMENT_FRAGMENT_NODE = 11;
  var ZWS = "\u200B";
  var ua = navigator.userAgent;
  var isMac = /Mac OS X/.test(ua);
  var isIOS = /iP(?:ad|hone)/.test(ua) || (isMac && !!navigator.maxTouchPoints);
  var isAndroid = /Android/.test(ua);
  var isWebKit = /WebKit\//.test(ua);
  var ctrlKey = isMac || isIOS ? "Meta-" : "Ctrl-";
  var cantFocusEmptyTextNodes = isWebKit;
  var notWS = /[^ \t\r\n]/;
  var indexOf = (array, value) => Array.prototype.indexOf.call(array, value);

  // source/node/Category.ts
  var inlineNodeNames = /^(?:#text|A|ABBR|ACRONYM|B|BR|BD[IO]|CITE|CODE|DATA|DEL|DFN|EM|FONT|HR|I|IMG|INPUT|INS|KBD|Q|RP|RT|RUBY|S|SAMP|SMALL|SPAN|STR(IKE|ONG)|SU[BP]|TIME|U|VAR|WBR)$/;
  var leafNodeNames = new Set(["BR", "HR", "IMG"]);
  var listNodeNames = new Set(["OL", "UL"]);
  var UNKNOWN = 0;
  var INLINE = 1;
  var BLOCK = 2;
  var CONTAINER = 3;
  var cache = new WeakMap();
  var isLeaf = (node) => isElement(node) && leafNodeNames.has(node.nodeName);
  var getNodeCategory = (node) => {
    switch (node.nodeType) {
      case TEXT_NODE:
        return INLINE;
      case ELEMENT_NODE:
      case DOCUMENT_FRAGMENT_NODE:
        if (cache.has(node)) {
          return cache.get(node);
        }
        break;
      default:
        return UNKNOWN;
    }
    let nodeCategory = Array.prototype.every.call(node.childNodes, isInline) ? (inlineNodeNames.test(node.nodeName) ? INLINE : BLOCK) : CONTAINER;
    cache.set(node, nodeCategory);
    return nodeCategory;
  };
  var isInline = (node) => getNodeCategory(node) === INLINE;
  var isBlock = (node) => getNodeCategory(node) === BLOCK;
  var isContainer = (node) => getNodeCategory(node) === CONTAINER;

  // source/node/Node.ts
  var createElement = (tag, props, children) => {
    const el = document.createElement(tag);
    if (props instanceof Array) {
      children = props;
      props = null;
    }
    setAttributes(el, props);
    children && el.append(...children);
    return el;
  };
  var areAlike = (node, node2) => !isLeaf(node) && (node.nodeType === node2.nodeType && node.nodeName === node2.nodeName && node.nodeName !== "A" && node.className === node2.className && node.style?.cssText === node2.style?.cssText);
  var hasTagAttributes = (node, tag, attributes) => node.nodeName === tag && Object.entries(attributes || {}).every(([k,v]) => node.getAttribute(k) === v);
  var getNearest = (node, root, tag, attributes) => {
    while (node && node !== root) {
      if (hasTagAttributes(node, tag, attributes)) {
        return node;
      }
      node = node.parentNode;
    }
    return null;
  };
  var getNodeBeforeOffset = (node, offset) => {
    let children = node.childNodes;
    while (offset && isElement(node)) {
      node = children[offset - 1];
      children = node.childNodes;
      offset = children.length;
    }
    return node;
  };
  var getNodeAfterOffset = (node, offset) => {
    if (isElement(node)) {
      const children = node.childNodes;
      if (offset < children.length) {
        node = children[offset];
      } else {
        while (node && !node.nextSibling) {
          node = node.parentNode;
        }
        node && (node = node.nextSibling);
      }
    }
    return node;
  };
  var getLength = (node) => isElement(node) || node instanceof DocumentFragment ? node.childNodes.length : node.length || 0;
  var empty = (node) => {
    const frag = document.createDocumentFragment(), childNodes = node.childNodes;
    childNodes && frag.append(...childNodes);
    return frag;
  };
  var detach = (node) => node.parentNode?.removeChild(node);
  var replaceWith = (node, node2) => node.parentNode?.replaceChild(node2, node);
  var getClosest = (node, root, selector) => {
    node = (node && !node.closest) ? node.parentElement : node;
    node = node?.closest(selector);
    return (node && root.contains(node)) ? node : null;
  };
  var isElement = (node) => node instanceof Element;
  var isTextNode = (node) => node instanceof Text;
  var isBrElement = (node) => "BR" === node?.nodeName;
  var setAttributes = (node, props) => {
    props && Object.entries(props).forEach(([k, v]) => {
      if (null == v) {
        node.removeAttribute(k);
      } else if ("style" === k && typeof v === "object") {
        Object.entries(v).forEach(([k2, v2]) => node.style[k2] = v2);
      } else {
        node.setAttribute(k, v);
      }
    });
  };

  // source/node/Whitespace.ts
  var notWSTextNode = (node) => isElement(node) ? isBrElement(node) : notWS.test(node.data);
  var isLineBreak = (br, isLBIfEmptyBlock) => {
    let block = br.parentNode;
    while (isInline(block)) {
      block = block.parentNode;
    }
    const walker = createTreeWalker(
      block,
      SHOW_ELEMENT_OR_TEXT,
      notWSTextNode
    );
    walker.currentNode = br;
    return !!walker.nextNode() || (isLBIfEmptyBlock && !walker.previousNode());
  };
  var removeZWS = (root, keepNode) => {
    const walker = createTreeWalker(root, SHOW_TEXT);
    let textNode;
    let index;
    while (textNode = walker.nextNode()) {
      while ((index = textNode.data.indexOf(ZWS)) > -1 && (!keepNode || textNode.parentNode !== keepNode)) {
        if (textNode.length === 1) {
          do {
            let parent = textNode.parentNode;
            textNode.remove();
            textNode = parent;
            walker.currentNode = parent;
          } while (isInline(textNode) && !getLength(textNode));
          break;
        } else {
          textNode.deleteData(index, 1);
        }
      }
    }
  };

  // source/range/Boundaries.ts
  var START_TO_START = 0;
  var START_TO_END = 1;
  var END_TO_END = 2;
  var END_TO_START = 3;
  var isNodeContainedInRange = (range, node, partial = true) => {
    const nodeRange = document.createRange();
    nodeRange.selectNode(node);
    return partial
      ? range.compareBoundaryPoints(END_TO_START, nodeRange) < 0
        && range.compareBoundaryPoints(START_TO_END, nodeRange) > 0
      : range.compareBoundaryPoints(START_TO_START, nodeRange) < 1
        && range.compareBoundaryPoints(END_TO_END, nodeRange) > -1;
  };
  var moveRangeBoundariesDownTree = range => {
    let { startContainer, startOffset, endContainer, endOffset } = range;
    while (!isTextNode(startContainer)) {
      let child = startContainer.childNodes[startOffset];
      if (!child || isLeaf(child)) {
        if (startOffset) {
          child = startContainer.childNodes[startOffset - 1];
          if (isTextNode(child)) {
            let prev;
            while (!child.length && (prev = child.previousSibling) && isTextNode(prev)) {
              child.remove();
              child = prev;
            }
            startContainer = child;
            startOffset = child.data.length;
          }
        }
        break;
      }
      startContainer = child;
      startOffset = 0;
    }
    if (endOffset) {
      while (!isTextNode(endContainer)) {
        const child = endContainer.childNodes[endOffset - 1];
        if (!child || isLeaf(child)) {
          if (isBrElement(child) && !isLineBreak(child)) {
            --endOffset;
            continue;
          }
          break;
        }
        endContainer = child;
        endOffset = getLength(endContainer);
      }
    } else {
      while (!isTextNode(endContainer)) {
        const child = endContainer.firstChild;
        if (!child || isLeaf(child)) {
          break;
        }
        endContainer = child;
      }
    }
    range.setStart(startContainer, startOffset);
    range.setEnd(endContainer, endOffset);
  };
  var moveRangeBoundariesUpTree = (range, startMax, endMax, root) => {
    let startContainer = range.startContainer;
    let startOffset = range.startOffset;
    let endContainer = range.endContainer;
    let endOffset = range.endOffset;
    let parent;
    if (!startMax) {
      startMax = range.commonAncestorContainer;
    }
    if (!endMax) {
      endMax = startMax;
    }
    while (!startOffset && startContainer !== startMax && startContainer !== root) {
      parent = startContainer.parentNode;
      startOffset = indexOf(parent.childNodes, startContainer);
      startContainer = parent;
    }
    while (endContainer !== endMax && endContainer !== root) {
      if (!isTextNode(endContainer) && isBrElement(endContainer.childNodes[endOffset]) && !isLineBreak(endContainer.childNodes[endOffset])) {
        ++endOffset;
      }
      if (endOffset !== getLength(endContainer)) {
        break;
      }
      parent = endContainer.parentNode;
      endOffset = indexOf(parent.childNodes, endContainer) + 1;
      endContainer = parent;
    }
    range.setStart(startContainer, startOffset);
    range.setEnd(endContainer, endOffset);
  };
  var moveRangeBoundaryOutOf = (range, tag, root) => {
    let parent = getClosest(range.endContainer, root, tag);
    if (parent && (parent = parent.parentNode)) {
      const clone = range.cloneRange();
      moveRangeBoundariesUpTree(clone, parent, parent, root);
      if (clone.endContainer === parent) {
        range.setStart(clone.endContainer, clone.endOffset);
        range.setEnd(clone.endContainer, clone.endOffset);
      }
    }
    return range;
  };

  // source/node/MergeSplit.ts
  var fixCursor = (node) => {
    let fixer = null;
    if (!isTextNode(node)) {
      if (isInline(node)) {
        let child = node.firstChild;
        if (cantFocusEmptyTextNodes) {
          while (isTextNode(child) && !child.data) {
            node.removeChild(child);
            child = node.firstChild;
          }
        }
        if (!child) {
          fixer = document.createTextNode(cantFocusEmptyTextNodes ? ZWS : "");
        }
      } else if (isElement(node) && !node.querySelector("BR")) {
        fixer = createElement("BR");
      }
      if (fixer) {
        try {
          node.appendChild(fixer);
        } catch (error) {
          didError({
            name: 'Squire: fixCursor – ' + error,
            message: 'Parent: ' + node.nodeName + '/' + node.innerHTML +
              ' appendChild: ' + fixer.nodeName
          });
        }
      }
    }
    return node;
  };
  var fixContainer = (container, root) => {
    let wrapper;
    [...container.childNodes].forEach((child) => {
      const isBR = isBrElement(child);
      if (!isBR && child.parentNode == root && isInline(child)) {
        wrapper = wrapper || createElement("DIV");
        wrapper.append(child);
      } else if (isBR || wrapper) {
        wrapper = wrapper || createElement("DIV");
        fixCursor(wrapper);
        child[isBR ? "replaceWith" : "before"](wrapper);
        wrapper = null;
      }
      isContainer(child) && fixContainer(child, root);
    });
    wrapper && container.append(fixCursor(wrapper));
    return container;
  };
  var split = (node, offset, stopNode, root) => {
    if (isTextNode(node) && node !== stopNode) {
      if (typeof offset !== "number") {
        throw new Error("Offset must be a number to split text node!");
      }
      if (!node.parentNode) {
        throw new Error("Cannot split text node with no parent!");
      }
      return split(node.parentNode, node.splitText(offset), stopNode, root);
    }
    let nodeAfterSplit = typeof offset === "number" ? offset < node.childNodes.length ? node.childNodes[offset] : null : offset;
    const parent = node.parentNode;
    if (!parent || node === stopNode || !isElement(node)) {
      return nodeAfterSplit;
    }
    const clone = node.cloneNode(false);
    while (nodeAfterSplit) {
      const next = nodeAfterSplit.nextSibling;
      clone.append(nodeAfterSplit);
      nodeAfterSplit = next;
    }
    if (node instanceof HTMLOListElement && getClosest(node, root, "BLOCKQUOTE")) {
      clone.start = (+node.start || 1) + node.childNodes.length - 1;
    }
    fixCursor(node);
    fixCursor(clone);
    node.after(clone);
    return split(parent, clone, stopNode, root);
  };
  var _mergeInlines = (node, fakeRange) => {
    const children = node.childNodes;
    let l = children.length;
    let frags = [];
    while (l--) {
      const child = children[l];
      const prev = l && children[l - 1];
      if (prev && isInline(child) && areAlike(child, prev)/* && !leafNodeNames.has(child.nodeName)*/) {
        if (fakeRange.startContainer === child) {
          fakeRange.startContainer = prev;
          fakeRange.startOffset += getLength(prev);
        }
        if (fakeRange.endContainer === child) {
          fakeRange.endContainer = prev;
          fakeRange.endOffset += getLength(prev);
        }
        if (fakeRange.startContainer === node) {
          if (fakeRange.startOffset > l) {
            --fakeRange.startOffset;
          } else if (fakeRange.startOffset === l) {
            fakeRange.startContainer = prev;
            fakeRange.startOffset = getLength(prev);
          }
        }
        if (fakeRange.endContainer === node) {
          if (fakeRange.endOffset > l) {
            --fakeRange.endOffset;
          } else if (fakeRange.endOffset === l) {
            fakeRange.endContainer = prev;
            fakeRange.endOffset = getLength(prev);
          }
        }
        detach(child);
        if (isTextNode(child)) {
          prev.appendData(child.data);
        } else {
          frags.unshift(empty(child));
        }
      } else if (isElement(child)) {
        child.append(...frags);
        frags = [];
        _mergeInlines(child, fakeRange);
      }
    }
  };
  var mergeInlines = (node, range) => {
    node = isTextNode(node) ? node.parentNode : node;
    if (isElement(node)) {
      const fakeRange = {
        startContainer: range.startContainer,
        startOffset: range.startOffset,
        endContainer: range.endContainer,
        endOffset: range.endOffset
      };
      _mergeInlines(node, fakeRange);
      range.setStart(fakeRange.startContainer, fakeRange.startOffset);
      range.setEnd(fakeRange.endContainer, fakeRange.endOffset);
    }
  };
  var mergeWithBlock = (block, next, range, root) => {
    let container = next;
    let parent;
    let offset;
    while ((parent = container.parentNode) && parent !== root && isElement(parent) && parent.childNodes.length === 1) {
      container = parent;
    }
    detach(container);
    offset = block.childNodes.length;
    const last = block.lastChild;
    if (isBrElement(last)) {
      last.remove();
      --offset;
    }
    block.append(empty(next));
    range.setStart(block, offset);
    range.collapse(true);
    mergeInlines(block, range);
  };
  var mergeContainers = (node, root) => {
    const prev = node.previousSibling;
    const first = node.firstChild;
    const isListItem = node.nodeName === "LI";
    if (isListItem && (!first || !listNodeNames.has(first.nodeName))) {
      return;
    }
    if (prev && areAlike(prev, node)) {
      if (!isContainer(prev)) {
        if (!isListItem) {
          return;
        }
        const block = createElement("DIV");
        block.append(empty(prev));
        prev.append(block);
      }
      detach(node);
      const needsFix = !isContainer(node);
      prev.append(empty(node));
      needsFix && fixContainer(prev, root);
      first && mergeContainers(first, root);
    } else if (isListItem) {
      const block = createElement("DIV");
      node.insertBefore(block, first);
      fixCursor(block);
    }
  };

  // source/Clean.ts
  var styleToSemantic = {
    fontWeight: {
      regexp: /^bold|^700/i,
      replace: () => createElement("B")
    },
    fontStyle: {
      regexp: /^italic/i,
      replace: () => createElement("I")
    },
    fontFamily: {
      regexp: notWS,
      replace: (family) => createElement("SPAN", {
        style: "font-family:" + family
      })
    },
    fontSize: {
      regexp: notWS,
      replace: (size) => createElement("SPAN", {
        style: "font-size:" + size
      })
    },
    textDecoration: {
      regexp: /^underline/i,
      replace: () => createElement("U")
    }
  /*
    textDecoration: {
      regexp: /^line-through/i,
      replace: doc => createElement("S")
    }
  */
  };
  var replaceStyles = (node) => {
    const style = node.style;
    let newTreeBottom;
    let newTreeTop;
    Object.entries(styleToSemantic).forEach(([attr, converter]) => {
      const css = style[attr];
      if (css && converter.regexp.test(css)) {
        const el = converter.replace(css);
        if (el.nodeName !== node.nodeName || el.className !== node.className) {
          if (!newTreeTop) {
            newTreeTop = el;
          }
          if (newTreeBottom) {
            newTreeBottom.append(el);
          }
          newTreeBottom = el;
          node.style.removeProperty(attr);
        }
      }
    });
    if (newTreeTop && newTreeBottom) {
      newTreeBottom.append(empty(node));
      if (node.style.cssText) {
        node.append(newTreeTop);
      } else {
        replaceWith(node, newTreeTop);
      }
    }
    return newTreeBottom || node;
  };
  var replaceWithTag = (tag) => (node) => {
    const el = createElement(tag);
    Array.prototype.forEach.call(node.attributes, (attr) => el.setAttribute(attr.name, attr.value));
    replaceWith(node, el);
    el.append(empty(node));
    return el;
  };
  var fontSizes = {
    1: "x-small",
    2: "small",
    3: "medium",
    4: "large",
    5: "x-large",
    6: "xx-large",
    7: "xxx-large",
    "-1": "smaller",
    "+1": "larger"
  };
  var stylesRewriters = {
    STRONG: replaceWithTag("B"),
    EM: replaceWithTag("I"),
    INS: replaceWithTag("U"),
    STRIKE: replaceWithTag("S"),
    SPAN: replaceStyles,
    FONT: (node) => {
      const face = node.face;
      const size = node.size;
      let color = node.color;
      let newTag = createElement("SPAN");
      let css = newTag.style;
      newTag.style.cssText = node.style.cssText;
      if (face) {
        css.fontFamily = face;
      }
      if (size) {
        css.fontSize = fontSizes[size];
      }
      if (color && /^#?([\dA-F]{3}){1,2}$/i.test(color)) {
        if (color.charAt(0) !== "#") {
          color = "#" + color;
        }
        css.color = color;
      }
      replaceWith(node, newTag);
      newTag.append(empty(node));
      return newTag;
    },
    TT: (node) => {
      const el = createElement("SPAN", {
        style: 'font-family:menlo,consolas,"courier new",monospace'
      });
      replaceWith(node, el);
      el.append(empty(node));
      return el;
    }
  };
  var allowedBlock = /^(?:A(?:DDRESS|RTICLE|SIDE|UDIO)|BLOCKQUOTE|CAPTION|D(?:[DLT]|IV)|F(?:IGURE|IGCAPTION|OOTER)|H[1-6]|HEADER|L(?:ABEL|EGEND|I)|O(?:L|UTPUT)|P(?:RE)?|SECTION|T(?:ABLE|BODY|D|FOOT|H|HEAD|R)|COL(?:GROUP)?|UL)$/;
  var blacklist = new Set(["HEAD", "META", "STYLE"]);
  var cleanTree = (node, preserveWS) => {
    const children = node.childNodes;
    let nonInlineParent = node;
    while (isInline(nonInlineParent)) {
      nonInlineParent = nonInlineParent.parentNode;
    }
/*
    const walker = createTreeWalker(
      nonInlineParent,
      SHOW_ELEMENT_OR_TEXT
    );
*/
    let i = children.length;
    while (i--) {
      let child = children[i];
      const nodeName = child.nodeName;
      if (isElement(child)) {
        const childLength = child.childNodes.length;
        if (stylesRewriters[nodeName]) {
          child = stylesRewriters[nodeName](child);
        } else if (blacklist.has(nodeName)) {
          child.remove();
          continue;
        } else if (!allowedBlock.test(nodeName) && !isInline(child)) {
          i += childLength;
          replaceWith(child, empty(child));
          continue;
        }
        if (childLength) {
          cleanTree(child, preserveWS || (nodeName === "PRE"));
        }
/*
      } else {
        if (isTextNode(child)) {
          let data = child.data;
          const startsWithWS = !notWS.test(data.charAt(0));
          const endsWithWS = !notWS.test(data.charAt(data.length - 1));
          if (preserveWS || (!startsWithWS && !endsWithWS)) {
            continue;
          }
          if (startsWithWS) {
            walker.currentNode = child;
            let sibling;
            while (sibling = walker.previousPONode()) {
              if (sibling.nodeName === "IMG" || isTextNode(sibling) && notWS.test(sibling.data)) {
                break;
              }
              if (!isInline(sibling)) {
                sibling = null;
                break;
              }
            }
            data = data.replace(/^[ \t\r\n]+/g, sibling ? " " : "");
          }
          if (endsWithWS) {
            walker.currentNode = child;
            let sibling;
            while (sibling = walker.nextNode()) {
              if (sibling.nodeName === "IMG" || (isTextNode(sibling) && notWS.test(sibling.data))) {
                break;
              }
              if (!isInline(sibling)) {
                sibling = null;
                break;
              }
            }
            data = data.replace(/[ \t\r\n]+$/g, sibling ? " " : "");
          }
          if (data) {
            child.data = data;
            continue;
          }
        }
        node.removeChild(child);
*/
      }
    }
    return node;
  };
  var removeEmptyInlines = (node) => {
    const children = node.childNodes;
    let l = children.length;
    while (l--) {
      const child = children[l];
      if (isElement(child) && !isLeaf(child)) {
        removeEmptyInlines(child);
        if (!child.firstChild && isInline(child)) {
          child.remove();
        }
      } else if (!child.data && isTextNode(child)) {
        node.removeChild(child);
      }
    }
  };
  var cleanupBRs = (node, root, keepForBlankLine) => {
    const brs = node.querySelectorAll("BR");
    let l = brs.length;
    while (l--) {
      const br = brs[l];
      const parent = br.parentNode;
      if (parent) {
        if (!isLineBreak(br, keepForBlankLine)) {
          detach(br);
        } else if (!isInline(parent)) {
          fixContainer(parent, root);
        }
      }
    }
  };
  var escapeHTML = (text) => text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

  // source/node/Block.ts
  var getBlockWalker = (node, root) => {
    const walker = createTreeWalker(root, SHOW_ELEMENT, isBlock);
    walker.currentNode = node;
    return walker;
  };
  var getPreviousBlock = (node, root) => {
    node = getBlockWalker(node, root).previousNode();
    return node !== root ? node : null;
  };
  var getNextBlock = (node, root) => {
    node = getBlockWalker(node, root).nextNode();
    return node !== root ? node : null;
  };
  var isEmptyBlock = (block) => !block.textContent && !block.querySelector("IMG");

  // source/range/Block.ts
  var getStartBlockOfRange = (range, root) => {
    const container = range.startContainer;
    let block;
    if (isInline(container)) {
      block = getPreviousBlock(container, root);
    } else if (container !== root && container instanceof HTMLElement && isBlock(container)) {
      block = container;
    } else {
      block = getNextBlock(getNodeBeforeOffset(container, range.startOffset), root);
    }
    return block && isNodeContainedInRange(range, block) ? block : null;
  };
  var getEndBlockOfRange = (range, root) => {
    const container = range.endContainer;
    let block;
    if (isInline(container)) {
      block = getPreviousBlock(container, root);
    } else if (container !== root && container instanceof HTMLElement && isBlock(container)) {
      block = container;
    } else {
      let node = getNodeAfterOffset(container, range.endOffset);
      if (!node || !root.contains(node)) {
        node = root;
        let child;
        while (child = node.lastChild) {
          node = child;
        }
      }
      block = getPreviousBlock(node, root);
    }
    return block && isNodeContainedInRange(range, block) ? block : null;
  };
  var createContentWalker = (root) => createTreeWalker(
    root,
    SHOW_ELEMENT_OR_TEXT,
    (node) => isTextNode(node) ? notWS.test(node.data) : node.nodeName === "IMG"
  );
  var rangeDoesStartAtBlockBoundary = (range, root) => {
    const startContainer = range.startContainer;
    const startOffset = range.startOffset;
    let nodeAfterCursor;
    if (isTextNode(startContainer)) {
      let i = startOffset;
      while (i--) {
        if (startContainer.data.charAt(i) !== ZWS) {
          return false;
        }
      }
      nodeAfterCursor = startContainer;
    } else {
      nodeAfterCursor = getNodeAfterOffset(startContainer, startOffset);
      if (!nodeAfterCursor || !root.contains(nodeAfterCursor)) {
        nodeAfterCursor = getNodeBeforeOffset(startContainer, startOffset);
        if (isTextNode(nodeAfterCursor) && nodeAfterCursor.length) {
          return false;
        }
      }
    }
    const block = getStartBlockOfRange(range, root);
    if (block) {
      const contentWalker = createContentWalker(block);
      contentWalker.currentNode = nodeAfterCursor;
      return !contentWalker.previousNode();
    }
  };
  var rangeDoesEndAtBlockBoundary = (range, root) => {
    const endContainer = range.endContainer;
    const endOffset = range.endOffset;
    let currentNode;
    if (isTextNode(endContainer)) {
      const text = endContainer.data;
      const length = text.length;
      for (let i = endOffset; i < length; ++i) {
        if (text.charAt(i) !== ZWS) {
          return false;
        }
      }
      currentNode = endContainer;
    } else {
      currentNode = getNodeBeforeOffset(endContainer, endOffset);
    }
    const block = getEndBlockOfRange(range, root);
    if (block) {
      const contentWalker = createContentWalker(block);
      contentWalker.currentNode = currentNode;
      return !contentWalker.nextNode();
    }
  };
  var expandRangeToBlockBoundaries = (range, root) => {
    const start = getStartBlockOfRange(range, root);
    const end = getEndBlockOfRange(range, root);
    if (start && end) {
      range.setStart(start, 0);
      range.setEnd(end, end.childNodes.length);
    }
  };

  // source/range/InsertDelete.ts
  var createRange = (startContainer, startOffset, endContainer, endOffset) => {
    const range = document.createRange();
    range.setStart(startContainer, startOffset);
    if (endContainer && typeof endOffset === "number") {
      range.setEnd(endContainer, endOffset);
    } else {
      range.setEnd(startContainer, startOffset);
    }
    return range;
  };
  var insertNodeInRange = (range, node) => {
    let { startContainer, startOffset, endContainer, endOffset } = range;
    let children;
    if (isTextNode(startContainer)) {
      const parent = startContainer.parentNode;
      children = parent.childNodes;
      if (startOffset === startContainer.length) {
        startOffset = indexOf(children, startContainer) + 1;
        if (range.collapsed) {
          endContainer = parent;
          endOffset = startOffset;
        }
      } else {
        if (startOffset) {
          const afterSplit = startContainer.splitText(startOffset);
          if (endContainer === startContainer) {
            endOffset -= startOffset;
            endContainer = afterSplit;
          } else if (endContainer === parent) {
            ++endOffset;
          }
          startContainer = afterSplit;
        }
        startOffset = indexOf(children, startContainer);
      }
      startContainer = parent;
    } else {
      children = startContainer.childNodes;
    }
    const childCount = children.length;
    if (startOffset === childCount) {
      startContainer.append(node);
    } else {
      startContainer.insertBefore(node, children[startOffset]);
    }
    if (startContainer === endContainer) {
      endOffset += children.length - childCount;
    }
    range.setStart(startContainer, startOffset);
    range.setEnd(endContainer, endOffset);
  };
  var extractContentsOfRange = (range, common, root) => {
    common = common || range.commonAncestorContainer;
    if (isTextNode(common)) {
      common = common.parentNode;
    }
    let endNode = split(range.endContainer, range.endOffset, common, root),
      frag = range.extractContents(),
      startContainer = common,
      startOffset = endNode ? indexOf(common.childNodes, endNode) : common.childNodes.length,
      after = common.childNodes[startOffset],
      before = after?.previousSibling,
      beforeText, afterText;
    if (isTextNode(before) && isTextNode(after)) {
      startContainer = before;
      startOffset = before.length;
      beforeText = before.data;
      afterText = after.data;
      if (beforeText.charAt(beforeText.length - 1) === ' ' && afterText.charAt(0) === ' ') {
        afterText = NBSP + afterText.slice(1);
      }
      before.appendData(afterText);
      detach(after);
    }
    range.setStart(startContainer, startOffset);
    range.collapse(true);
    fixCursor(common);
    return frag;
  };
  var getAdjacentInlineNode = (iterator, method, node) => {
    iterator.currentNode = node;
    let nextNode;
    while (nextNode = iterator[method]()) {
      if (isTextNode(nextNode) || isLeaf(nextNode)) {
        return nextNode;
      }
      if (!isInline(nextNode)) {
        return null;
      }
    }
    return null;
  };
  var deleteContentsOfRange = (range, root) => {
    const startBlock = getStartBlockOfRange(range, root);
    let endBlock = getEndBlockOfRange(range, root);
    const needsMerge = startBlock !== endBlock;
    if (startBlock && endBlock) {
      moveRangeBoundariesDownTree(range);
      moveRangeBoundariesUpTree(range, startBlock, endBlock, root);
    }
    const frag = extractContentsOfRange(range, null, root);
    moveRangeBoundariesDownTree(range);
    if (needsMerge) {
      endBlock = getEndBlockOfRange(range, root);
      if (startBlock && endBlock && startBlock !== endBlock) {
        mergeWithBlock(startBlock, endBlock, range, root);
      }
    }
    if (startBlock) {
      fixCursor(startBlock);
    }
    const child = root.firstChild;
    if (!child || isBrElement(child)) {
      fixCursor(root);
      root.firstChild && range.selectNodeContents(root.firstChild);
    }
    range.collapse(true);
    const startContainer = range.startContainer;
    const startOffset = range.startOffset;
    const iterator = createTreeWalker(root, SHOW_ELEMENT_OR_TEXT);
    let afterNode = startContainer;
    let afterOffset = startOffset;
    if (!isTextNode(afterNode) || afterOffset === afterNode.data.length) {
      afterNode = getAdjacentInlineNode(iterator, "nextNode", afterNode);
      afterOffset = 0;
    }
    let beforeNode = startContainer;
    let beforeOffset = startOffset - 1;
    if (!isTextNode(beforeNode) || beforeOffset === -1) {
      beforeNode = getAdjacentInlineNode(
        iterator,
        "previousPONode",
        afterNode || (isTextNode(startContainer) ? startContainer : startContainer.childNodes[startOffset] || startContainer)
      );
      if (isTextNode(beforeNode)) {
        beforeOffset = beforeNode.data.length;
      }
    }
    let node = null;
    let offset = 0;
    if (isTextNode(afterNode) && afterNode.data.charAt(afterOffset) === " " && rangeDoesStartAtBlockBoundary(range, root)) {
      node = afterNode;
      offset = afterOffset;
    } else if (isTextNode(beforeNode) && beforeNode.data.charAt(beforeOffset) === " ") {
      if (isTextNode(afterNode) && afterNode.data.charAt(afterOffset) === " " || rangeDoesEndAtBlockBoundary(range, root)) {
        node = beforeNode;
        offset = beforeOffset;
      }
    }
    node && node.replaceData(offset, 1, "\xA0");
    range.setStart(startContainer, startOffset);
    range.collapse(true);
    return frag;
  };
  var insertTreeFragmentIntoRange = (range, frag, root) => {
    const firstInFragIsInline = frag.firstChild && isInline(frag.firstChild);
    let node, blockContentsAfterSplit;
    fixContainer(frag, root);
    node = frag;
    while (node = getNextBlock(node, root)) {
      fixCursor(node);
    }
    if (!range.collapsed) {
      deleteContentsOfRange(range, root);
    }
    moveRangeBoundariesDownTree(range);
    range.collapse();
    const stopPoint = getClosest(range.endContainer, root, "BLOCKQUOTE") || root;
    let block = getStartBlockOfRange(range, root);
    const firstBlockInFrag = getNextBlock(frag, frag);
    const replaceBlock = !firstInFragIsInline && !!block && isEmptyBlock(block);
    if (block && firstBlockInFrag && !replaceBlock &&
    !getClosest(firstBlockInFrag, frag, "PRE,TABLE")) {
      moveRangeBoundariesUpTree(range, block, block, root);
      range.collapse(true);
      let container = range.endContainer;
      let offset = range.endOffset;
      cleanupBRs(block, root, false);
      if (isInline(container)) {
        const nodeAfterSplit = split(
          container,
          offset,
          getPreviousBlock(container, root) || root,
          root
        );
        container = nodeAfterSplit.parentNode;
        offset = indexOf(container.childNodes, nodeAfterSplit);
      }
      if (
        /*isBlock(container) && */
        offset !== getLength(container)
      ) {
        blockContentsAfterSplit = document.createDocumentFragment();
        while (node = container.childNodes[offset]) {
          blockContentsAfterSplit.append(node);
        }
      }
      mergeWithBlock(container, firstBlockInFrag, range, root);
      offset = indexOf(container.parentNode.childNodes, container) + 1;
      container = container.parentNode;
      range.setEnd(container, offset);
    }
    if (getLength(frag)) {
      if (replaceBlock && block) {
        range.setEndBefore(block);
        range.collapse();
        detach(block);
      }
      moveRangeBoundariesUpTree(range, stopPoint, stopPoint, root);
      let nodeAfterSplit = split(
        range.endContainer,
        range.endOffset,
        stopPoint,
        root
      );
      const nodeBeforeSplit = nodeAfterSplit ? nodeAfterSplit.previousSibling : stopPoint.lastChild;
      stopPoint.insertBefore(frag, nodeAfterSplit);
      if (nodeAfterSplit) {
        range.setEndBefore(nodeAfterSplit);
      } else {
        range.setEnd(stopPoint, getLength(stopPoint));
      }
      block = getEndBlockOfRange(range, root);
      moveRangeBoundariesDownTree(range);
      const container = range.endContainer;
      const offset = range.endOffset;
      if (nodeAfterSplit && isContainer(nodeAfterSplit)) {
        mergeContainers(nodeAfterSplit, root);
      }
      nodeAfterSplit = nodeBeforeSplit?.nextSibling;
      if (nodeAfterSplit && isContainer(nodeAfterSplit)) {
        mergeContainers(nodeAfterSplit, root);
      }
      range.setEnd(container, offset);
    }
    if (blockContentsAfterSplit && block) {
      const tempRange = range.cloneRange();
      mergeWithBlock(block, blockContentsAfterSplit, tempRange, root);
      range.setEnd(tempRange.endContainer, tempRange.endOffset);
    }
    moveRangeBoundariesDownTree(range);
  };

  // source/range/Contents.ts
/*
  var getTextContentsOfRange = (range) => {
    if (range.collapsed) {
      return "";
    }
    const startContainer = range.startContainer;
    const endContainer = range.endContainer;
    const filter = (node2) => isNodeContainedInRange(range, node2, true);
    const walker = createTreeWalker(
      range.commonAncestorContainer,
      SHOW_ELEMENT_OR_TEXT,
      filter
    );
    walker.currentNode = startContainer;
    let node = startContainer;
    let textContent = "";
    let addedTextInBlock = false;
    let value;
    if (!isElement(node) && !isTextNode(node) || !filter(node)) {
      node = walker.nextNode();
    }
    while (node) {
      if (isTextNode(node)) {
        value = node.data;
        if (value && /\S/.test(value)) {
          if (node === endContainer) {
            value = value.slice(0, range.endOffset);
          }
          if (node === startContainer) {
            value = value.slice(range.startOffset);
          }
          textContent += value;
          addedTextInBlock = true;
        }
      } else if (isBrElement(node) || addedTextInBlock && !isInline(node)) {
        textContent += "\n";
        addedTextInBlock = false;
      }
      node = walker.nextNode();
    }
    textContent = textContent.replace(/\xA0/g, " ");
    return textContent;
  };
*/

  // source/Clipboard.ts
  var extractRangeToClipboard = (event, range, root, cut) => {
    if (event.clipboardData) {
      let startBlock = getStartBlockOfRange(range, root),
        endBlock = getEndBlockOfRange(range, root),
        copyRoot = ((startBlock === endBlock) && startBlock) || root,
        contents, parent, newContents;
      if (cut) {
        contents = deleteContentsOfRange(range, root);
      } else {
        range = range.cloneRange();
        moveRangeBoundariesDownTree(range);
        moveRangeBoundariesUpTree(range, copyRoot, copyRoot, root);
        contents = range.cloneContents();
      }
      parent = range.commonAncestorContainer;
      if (isTextNode(parent)) {
        parent = parent.parentNode;
      }
      while (parent && parent !== copyRoot) {
        newContents = parent.cloneNode(false);
        newContents.append(contents);
        contents = newContents;
        parent = parent.parentNode;
      }
      let clipboardData = event.clipboardData;
      let body = document.body;
      let node = createElement("div");
      let html, text;
      node.append(contents);
      html = node.innerHTML;
      cleanupBRs(node, root, true);
      node.setAttribute("style",
        'position:fixed;overflow:hidden;bottom:100%;right:100%;');
      body.append(node);
      text = (node.innerText || node.textContent).replace(NBSP, ' '); // Replace nbsp with regular space
      node.remove();
      if (text !== html) {
        clipboardData.setData("text/html", html);
      }
      clipboardData.setData("text/plain", text);
      event.preventDefault();
      return true;
    }
  };
  var _onCut = function(event) {
    const range = this.getSelection();
    const root = this._root;
    if (range.collapsed) {
      event.preventDefault();
      return;
    }
    this.saveUndoState(range);
    if (!extractRangeToClipboard(event, range, root, true)) {
      setTimeout(() => {
        try {
          this._ensureBottomLine();
        } catch (error) {
          didError(error);
        }
      }, 0);
    }
    this.setSelection(range);
  };
  var _onCopy = function(event) {
    extractRangeToClipboard(
      event,
      this.getSelection(),
      this._root
    );
  };
  var _onPaste = function(event) {
    const clipboardData = event.clipboardData;
    const items = clipboardData?.items;
    let imageItem = null;
    let plainItem = null;
    let htmlItem = null;
    let self = this;
    let type;
    if (items) {
      [...items].forEach(item => {
        type = item.type;
        if (type === "text/html") {
          htmlItem = item;
        } else if (type === "text/plain" || type === "text/uri-list") {
          plainItem = item;
        } else if (item.kind === "file" && /^image\/(png|jpeg|webp)/.test(type)) {
          imageItem = item;
        }
      });
      if (htmlItem || plainItem || imageItem) {
        event.preventDefault();
        if (imageItem) {
          let reader = new FileReader();
          reader.onload = (event) => {
            let img = createElement("img", {src: event.target.result}),
              canvas = createElement("canvas"),
              ctx = canvas.getContext('2d');
            img.onload = ()=>{
              ctx.drawImage(img, 0, 0);
              let width = img.width, height = img.height;
              if (width > height) {
                if (width > 1024) {
                  height = height * 1024 / width;
                  width = 1024;
                }
              } else if (height > 1024) {
                width = width * 1024 / height;
                height = 1024;
              }
              canvas.width = width;
              canvas.height = height;
              ctx.drawImage(img, 0, 0, width, height);
              self.insertHTML('<img alt="" style="width:100%;max-width:'+width+'px" src="'+canvas.toDataURL()+'">', true);
            };
          }
          reader.readAsDataURL(imageItem.getAsFile());
        } else if (htmlItem && (!self.isShiftDown || !plainItem)) {
          htmlItem.getAsString(html => self.insertHTML(html, true));
        } else if (plainItem) {
          plainItem.getAsString(text => self.insertPlainText(text, true));
        }
      }
    }
  };

  // source/keyboard/KeyHelpers.ts
  var afterDelete = (self, range) => {
    try {
      range = range || self.getSelection();
      let node = range.startContainer;
      if (isTextNode(node)) {
        node = node.parentNode;
      }
      let parent = node;
      while (isInline(parent) && (!parent.textContent || parent.textContent === ZWS)) {
        node = parent;
        parent = node.parentNode;
      }
      if (node !== parent) {
        range.setStart(
          parent,
          indexOf(parent.childNodes, node)
        );
        range.collapse(true);
        node.remove();
        if (!isBlock(parent)) {
          parent = getPreviousBlock(parent, self._root) || parent;
        }
        fixCursor(parent);
        moveRangeBoundariesDownTree(range);
      }
      if (node === self._root && (node = node.firstChild) && isBrElement(node)) {
        detach(node);
      }
      self._ensureBottomLine();
      self.setRange(range);
    } catch (error) {
      didError(error);
    }
  };

  // source/keyboard/Backspace.ts
  var Backspace = (self, event, range) => {
    const root = self._root;
    self._removeZWS();
    self.saveUndoState(range);
    if (!range.collapsed) {
      event.preventDefault();
      deleteContentsOfRange(range, root);
      afterDelete(self, range);
    } else if (rangeDoesStartAtBlockBoundary(range, root)) {
      event.preventDefault();
      let current = getStartBlockOfRange(range, root);
      let previous;
      if (!current) {
        return;
      }
      fixContainer(current.parentNode, root);
      previous = getPreviousBlock(current, root);
      if (previous) {
        if (!previous.isContentEditable) {
          detachUneditableNode(previous, root);
          return;
        }
        mergeWithBlock(previous, current, range, root);
        current = previous.parentNode;
        while (current !== root && !current.nextSibling) {
          current = current.parentNode;
        }
        if (current !== root && (current = current.nextSibling)) {
          mergeContainers(current, root);
        }
        self.setSelection(range);
      } else if (current) {
        if (decreaseLevel(self, range, current)) {
          return;
        }
        self.setRange(range);
      }
    } else {
      self.setSelection(range);
      setTimeout(() => afterDelete(self), 0);
    }
  };

  // source/keyboard/Delete.ts
  var Delete = (self, event, range) => {
    const root = self._root;
    let current;
    let next;
    let originalRange;
    let cursorContainer;
    let cursorOffset;
    let nodeAfterCursor;
    self._removeZWS();
    self.saveUndoState(range);
    if (!range.collapsed) {
      event.preventDefault();
      deleteContentsOfRange(range, root);
      afterDelete(self, range);
    } else if (rangeDoesEndAtBlockBoundary(range, root)) {
      event.preventDefault();
      if (current = getStartBlockOfRange(range, root)) {
        fixContainer(current.parentNode, root);
        if (next = getNextBlock(current, root)) {
          if (!next.isContentEditable) {
            detachUneditableNode(next, root);
            return;
          }
          mergeWithBlock(current, next, range, root);
          next = current.parentNode;
          while (next !== root && !next.nextSibling) {
            next = next.parentNode;
          }
          if (next !== root && (next = next.nextSibling)) {
            mergeContainers(next, root);
          }
          self.setRange(range);
        }
      }
    } else {
      originalRange = range.cloneRange();
      moveRangeBoundariesUpTree(range, root, root, root);
      cursorContainer = range.endContainer;
      cursorOffset = range.endOffset;
      if (isElement(cursorContainer)) {
        nodeAfterCursor = cursorContainer.childNodes[cursorOffset];
        if (nodeAfterCursor?.nodeName === "IMG") {
          event.preventDefault();
          detach(nodeAfterCursor);
          moveRangeBoundariesDownTree(range);
          afterDelete(self, range);
          return;
        }
      }
      self.setSelection(originalRange);
      setTimeout(() => afterDelete(self), 0);
    }
  };

  // source/keyboard/Tab.ts
  var Tab = (self, event, range) => {
    self._removeZWS();
    range.collapsed
      && rangeDoesStartAtBlockBoundary(range, self._root)
      && getClosest(range.startContainer, self._root, "UL,OL,BLOCKQUOTE")
      && self.changeIndentationLevel("increase")
      && event.preventDefault();
  };
  var ShiftTab = (self, event, range) => {
    self._removeZWS();
    range.collapsed
      && rangeDoesStartAtBlockBoundary(range, self._root)
      && decreaseLevel(self, range, range.startContainer)
      && event.preventDefault();
  };

  // source/keyboard/Space.ts
  var Space = (self, event, range) => {
/*
    var _a;
    let node;
    const root = self._root;
    self._recordUndoState(range);
    self._getRangeAndRemoveBookmark(range);
    if (!range.collapsed) {
      deleteContentsOfRange(range, root);
      self._ensureBottomLine();
      self.setSelection(range);
      self._updatePath(range, true);
    } else if (rangeDoesEndAtBlockBoundary(range, root)) {
      const block = getStartBlockOfRange(range, root);
      if (block && block.nodeName !== "PRE") {
        const text = block.textContent?.trimEnd().replace(ZWS, "");
        if (text === "*" || text === "1.") {
          event.preventDefault();
          const walker = createTreeWalker(block, SHOW_TEXT);
          let textNode;
          while (textNode = walker.nextNode()) {
            textNode.data = cantFocusEmptyTextNodes ? ZWS : "";
          }
          if (text === "*") {
            self.makeUnorderedList();
          } else {
            self.makeOrderedList();
          }
          return;
        }
      }
    }
    node = range.endContainer;
    if (range.endOffset === getLength(node)) {
      do {
        if (node.nodeName === "A") {
          range.setStartAfter(node);
          break;
        }
      } while (!node.nextSibling && (node = node.parentNode) && node !== root);
    }
    if (self._config.addLinks) {
      const linkRange = range.cloneRange();
      moveRangeBoundariesDownTree(linkRange);
      const textNode = linkRange.startContainer;
      const offset = linkRange.startOffset;
      setTimeout(() => {
        linkifyText(self, textNode, offset);
      }, 0);
    }
    self.setSelection(range);
*/
    const root = self._root;
    self._recordUndoState(range);
    self._config.addLinks && addLinks(range.startContainer, root);
    self._getRangeAndRemoveBookmark(range);
/*
    let node = range.endContainer;
    if (range.collapsed && range.endOffset === getLength(node)) {
      do {
        if (node.nodeName === "A") {
          range.setStartAfter(node);
          break;
        }
      } while (!node.nextSibling && (node = node.parentNode) && node !== root);
    }
*/
    if (!range.collapsed) {
      deleteContentsOfRange(range, root);
      self._ensureBottomLine();
    }
    self.setRange(range);
  };

  // source/keyboard/KeyHandlers.ts
  var _onKey = function(event) {
    if (event.defaultPrevented) {
      return;
    }
    let key = event.key,
      range = this.getSelection(),
      root = this._root;
    if (key !== "Backspace" && key !== "Delete") {
      if (event.shiftKey) {
        key = "Shift-" + key;
      }
      if (event[osKey]) { key = ctrlKey + key; }
    }
    if (this._keyHandlers[key]) {
      this._keyHandlers[key](this, event, range);
    } else if (!range.collapsed && !event.isComposing && !event[osKey] && key.length === 1) {
      this.saveUndoState(range);
      deleteContentsOfRange(range, root);
      this._ensureBottomLine();
      this.setRange(range);
    } else if (range.collapsed && range.startContainer === root && root.children.length > 0) {
      const nextElement = root.children[range.startOffset];
      if (nextElement && !isBlock(nextElement)) {
        range = createRange(root.insertBefore(
          this.createDefaultBlock(), nextElement
        ), 0);
        if (isBrElement(nextElement)) {
          root.removeChild(nextElement);
        }
        const restore = this._willRestoreSelection;
        this.setSelection(range);
        this._willRestoreSelection = restore;
      }
    }
  };
  var mapKeyToFormat = (tag, remove) => {
    return (self, event) => {
      event.preventDefault();
      self.toggleTag(tag, remove);
    };
  };
  var mapKeyTo = (method) => (self, event) => {
    event.preventDefault();
    self[method]();
  };
  var toggleList = (type, methodIfNotInList) => (self, event) => {
    event.preventDefault();
    let parent = self.getSelectionClosest("UL,OL");
    if (type == parent?.nodeName) {
      self.removeList();
    } else {
      self[methodIfNotInList]();
    }
  };
  var changeIndentationLevel = (direction) => (self, event) => {
    event.preventDefault();
    self.changeIndentationLevel(direction);
  };
  var keyHandlers = {
    Tab,
    "Shift-Tab": ShiftTab,
    Space,
    ArrowLeft(self) {
      self._removeZWS();
    },
    ArrowRight(self) {
      self._removeZWS()
    },
    [ctrlKey + "b"]: mapKeyToFormat("B"),
    [ctrlKey + "i"]: mapKeyToFormat("I"),
    [ctrlKey + "u"]: mapKeyToFormat("U"),
    [ctrlKey + "Shift-7"]: mapKeyToFormat("S"),
    [ctrlKey + "Shift-5"]: mapKeyToFormat("SUB", "SUP"),
    [ctrlKey + "Shift-6"]: mapKeyToFormat("SUP", "SUB"),
    [ctrlKey + "Shift-8"]: toggleList("UL", "makeUnorderedList"),
    [ctrlKey + "Shift-9"]: toggleList("OL", "makeOrderedList"),
    [ctrlKey + "["]: changeIndentationLevel("decrease"),
    [ctrlKey + "]"]: changeIndentationLevel("increase"),
    [ctrlKey + "d"]: mapKeyTo("toggleCode"),
//    [ctrlKey + "z"]: mapKeyTo("undo"), // historyUndo
    [ctrlKey + "y"]: mapKeyTo("redo"), // historyRedo
    [ctrlKey + "Shift-Z"]: mapKeyTo("redo"),
    ["Redo"]: mapKeyTo("redo")
  };
  var blockTag = "DIV";
  var DOCUMENT_POSITION_PRECEDING = 2;

  var NBSP = '\u00A0';
  var win = document.defaultView;
  var osKey = isMac ? "metaKey" : "ctrlKey";
/*
  typeToBitArray = {
    1: 1,
    2: 2,
    3: 4,
    8: 128,
    9: 256,
    11: 1024
  },
*/

  var didError = error => console.error(error);
  var detachUneditableNode = (node, root) => {
    let parent;
    while (parent = node.parentNode) {
      if (parent === root || parent.isContentEditable) {
        break;
      }
      node = parent;
    }
    detach(node);
  };

  var mergeObjects = (base, extras, mayOverride) => {
    base = base || {};
    extras && Object.entries(extras).forEach(([prop,value])=>{
      if (mayOverride || !(prop in base)) {
        base[prop] = (value?.constructor === Object) ?
          mergeObjects(base[prop], value, mayOverride) :
          value;
      }
    });
    return base;
  };

  var createBookmarkNodes = () => [
    createElement("INPUT", {
      id: startSelectionId,
      type: "hidden"
    }),
    createElement("INPUT", {
      id: endSelectionId,
      type: "hidden"
    })
  ];

  var getListSelection = (range, root) => {
    let list = range.commonAncestorContainer;
    let startLi = range.startContainer;
    let endLi = range.endContainer;
    while (list && list !== root && !listNodeNames.has(list.nodeName)) {
      list = list.parentNode;
    }
    if (!list || list === root) {
      return null;
    }
    if (startLi === list) {
      startLi = startLi.childNodes[range.startOffset];
    }
    if (endLi === list) {
      endLi = endLi.childNodes[range.endOffset];
    }
    while (startLi && startLi.parentNode !== list) {
      startLi = startLi.parentNode;
    }
    while (endLi && endLi.parentNode !== list) {
      endLi = endLi.parentNode;
    }
    return [list, startLi, endLi];
  };
  var setDirection = (self, frag, dir) => {
    let walker = getBlockWalker(frag, self._root),
      node;
    while (node = walker.nextNode()) {
      if (node.nodeName === "LI") {
        node.parentNode.setAttribute("dir", dir);
        break;
      }
      node.setAttribute("dir", dir);
    }
    return frag;
  };
  var decreaseLevel = (self, range, node) =>
    getClosest(node, self._root, "UL,OL,BLOCKQUOTE") && self.changeIndentationLevel("decrease");
  var addLinks = (frag, root) => {
    let walker = createTreeWalker(frag, SHOW_TEXT, node => !getClosest(node, root, "A"));
    let node, data, parent, match, index, endIndex, child;
    while (node = walker.nextNode()) {
      data = node.data;
      parent = node.parentNode;
      while (match = linkRegExp.exec(data)) {
        index = match.index;
        endIndex = index + match[0].length;
        if (index) {
          child = document.createTextNode(data.slice(0, index));
          parent.insertBefore(child, node);
        }
        child = createElement("A", {
          href: match[1]
            ? (match[2] ? match[1] : "https://" + match[1])
            : "mailto:" + match[0]
        }, [data.slice(index, endIndex)]);
        parent.insertBefore(child, node);
        node.data = data = data.slice(endIndex);
      }
    }
  };

keyHandlers[ctrlKey + "b"] = mapKeyToFormat("B");
keyHandlers[ctrlKey + "i"] = mapKeyToFormat("I");
keyHandlers[ctrlKey + "u"] = mapKeyToFormat("U");
keyHandlers[ctrlKey + "Shift-7"] = mapKeyToFormat("S");
keyHandlers[ctrlKey + "Shift-5"] = mapKeyToFormat("SUB", "SUP");
keyHandlers[ctrlKey + "Shift-6"] = mapKeyToFormat("SUP", "SUB");
keyHandlers[ctrlKey + "Shift-8"] = toggleList("UL", "makeUnorderedList");
keyHandlers[ctrlKey + "Shift-9"] = toggleList("OL", "makeOrderedList");
keyHandlers[ctrlKey + "["] = changeIndentationLevel("decrease");
keyHandlers[ctrlKey + "]"] = changeIndentationLevel("increase");
keyHandlers[ctrlKey + "d"] = mapKeyTo("toggleCode");
keyHandlers[ctrlKey + "y"] = mapKeyTo("redo");
keyHandlers[ctrlKey + "Shift-Z"] = mapKeyTo("redo");
keyHandlers["Redo"] = mapKeyTo("redo");

class EditStack extends Array
{
    constructor(squire) {
      super();
      this.squire = squire;
      this.index = -1;
      this.inUndoState = false;
      this.limit = 0; // -1 means no limit
    }

    clear() {
      this.index = -1;
      this.length = 0;
    }

    stateChanged(/*canUndo, canRedo*/) {
      this.squire.fireEvent("undoStateChange", {
        canUndo: this.index > 0,
        canRedo: this.index + 1 < this.length
      });
      this.squire.fireEvent("input");
    }

    docWasChanged() {
      if (this.inUndoState) {
        this.inUndoState = false;
        this.stateChanged(/*true, false*/);
      } else
        this.squire.fireEvent("input");
    }

    /**
     * Leaves bookmark.
     */
    recordUndoState(range, replace) {
      if (!this.inUndoState || replace) {
        let undoIndex = this.index;
        let undoLimit = this.limit;
        let squire = this.squire;
        replace || ++undoIndex;
        undoIndex = Math.max(0, undoIndex);
        this.length = Math.min(undoIndex + 1, this.length);
        range && squire._saveRangeToBookmark(range);
        const html = squire._getRawHTML();
        if (undoLimit > 0 && undoIndex > undoLimit) {
          this.splice(0, undoIndex - undoLimit);
          undoIndex = undoLimit;
        }
        this[undoIndex] = html;
        this.index = undoIndex;
        this.inUndoState = true;
      }
    }

    saveUndoState(range) {
      let squire = this.squire;
      range = range || squire.getSelection();
      this.recordUndoState(range, true);
      squire._getRangeAndRemoveBookmark(range);
    }

    undo() {
      let squire = this.squire;
      if (this.index > 0 || !this.inUndoState) {
        this.recordUndoState(squire.getSelection());
        const undoIndex = this.index - 1;
        this.index = undoIndex;
        squire._setRawHTML(this[undoIndex]);
        let range = squire._getRangeAndRemoveBookmark();
        if (range) {
          squire.setSelection(range);
        }
        this.stateChanged(/*undoIndex > 0, true*/);
      }
    }

    redo() {
      let squire = this.squire,
        undoIndex = this.index + 1;
      if (undoIndex < this.length && this.inUndoState) {
        this.index = undoIndex;
        squire._setRawHTML(this[undoIndex]);
        let range = squire._getRangeAndRemoveBookmark();
        if (range) {
          squire.setSelection(range);
        }
        this.stateChanged(/*true, undoIndex + 1 < this.length*/);
      }
    }
}

  // source/Editor.ts
  var customEvents = new Set([
    "pathChange",
    "select",
    "input",
    "pasteImage",
    "undoStateChange"
  ]);
  var startSelectionId = "squire-selection-start";
  var endSelectionId = "squire-selection-end";
  var tagAfterSplit = {
    DT: "DD",
    DD: "DT",
    LI: "LI",
    PRE: "PRE"
  };
  var linkRegExp = /\b(?:((https?:\/\/)?(?:www\d{0,3}\.|[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\/)(?:[^\s()<>]+|\([^\s()<>]+\))+(?:[^\s?&`!()[\]{};:'".,<>«»“”‘’]|\([^\s()<>]+\)))|([\w\-.%+]+@(?:[\w-]+\.)+[a-z]{2,}\b(?:\?[^&?\s]+=[^\s?&`!()[\]{};:'".,<>«»“”‘’]+(?:&[^&?\s]+=[^\s?&`!()[\]{};:'".,<>«»“”‘’]+)*)?))/i;
  var Squire = class {
    constructor(root, config) {
      this._root = root;
      this.setConfig(config);
      this._isFocused = false;
      this._lastSelection = null;
      this._willRestoreSelection = false;
      this._mayHaveZWS = false;
      this._path = "";
      this._pathRange = null;
      this._events = new Map();
      this.editStack = new EditStack(this);
      this._ignoreChange = false;
      this.addEventListener("selectionchange", () => this._isFocused && this._updatePath(this.getSelection()))
        .addEventListener("blur", () => this._willRestoreSelection = true)
        .addEventListener("pointerdown mousedown touchstart", () => this._willRestoreSelection = false)
        .addEventListener("focus", () => this._willRestoreSelection && this.setSelection(this._lastSelection))
        .addEventListener("cut", _onCut)
        .addEventListener("copy", _onCopy)
        .addEventListener("paste", _onPaste)
        .addEventListener("drop", (event) => {
          let types = event.dataTransfer.types;
          if (types.includes("text/plain") || types.includes("text/html")) {
            this.saveUndoState();
          }
        })
        .addEventListener("keydown keyup", (event) => this.isShiftDown = event.shiftKey)
        .addEventListener("keydown", _onKey)
        .addEventListener("pointerup keyup mouseup touchend", () => this.getSelection())
        .addEventListener("beforeinput", this._beforeInput);
      this._keyHandlers = Object.create(keyHandlers);
      this._mutation = new MutationObserver(() => this._docWasChanged());
      this._mutation.observe(root, {
        childList: true,
        attributes: true,
        characterData: true,
        subtree: true
      });
      root.setAttribute("contenteditable", "true");
      this.setHTML("");
      this._beforeInputTypes = {
        insertText: (event) => {
          if (isAndroid && event.data && event.data.includes("\n")) {
            event.preventDefault();
          }
        },
        insertLineBreak: (event) => {
          event.preventDefault();
          this.splitBlock(true);
        },
        insertParagraph: (event) => {
          event.preventDefault();
          this.splitBlock(false);
        },
        insertOrderedList: (event) => {
          event.preventDefault();
          this.makeOrderedList();
        },
        insertUnoderedList: (event) => {
          event.preventDefault();
          this.makeUnorderedList();
        },
        historyUndo: (event) => {
          event.preventDefault();
          this.undo();
        },
        historyRedo: (event) => {
          event.preventDefault();
        },
        formatRemove: (event) => {
          event.preventDefault();
          this.setStyle();
        },
        formatSetBlockTextDirection: (event) => {
          event.preventDefault();
          let dir = event.data;
          this.setTextDirection(dir === "null" ? null : dir);
        },
        formatBackColor: (event) => {
          event.preventDefault();
          this.setStyle({ backgroundColor: event.data });
        },
        formatFontColor: (event) => {
          event.preventDefault();
          this.setStyle({ color: event.data });
        },
        formatFontName: (event) => {
          event.preventDefault();
          this.setStyle({ fontFamily: event.data });
        },
/*
        formatIndent: event => {
          event.preventDefault();
          this.changeIndentationLevel("increase");
        },
        formatOutdent: event => {
          event.preventDefault();
          this.changeIndentationLevel("decrease");
        },
          this.saveUndoState();
        },
*/
        deleteContentBackward: (event) => {
          Backspace(this, event, this.getSelection());
        },
        deleteContentForward: (event) => {
          Delete(this, event, this.getSelection());
        }
      };
    }

    _beforeInput(event) {
      let type = event.isComposing ? "" : event.inputType;
      switch (type) {
        case "formatBold":
        case "formatItalic":
        case "formatUnderline":
        case "formatStrikeThrough":
        case "formatSuperscript":
        case "formatSubscript":
          event.preventDefault();
          this[type.slice(6).toLowerCase()]();
          break;
        case "formatJustifyFull":
        case "formatJustifyCenter":
        case "formatJustifyRight":
        case "formatJustifyLeft": {
          event.preventDefault();
          let alignment = type.slice(13).toLowerCase();
          this.setStyle({textAlign:alignment === "full" ? "justify" : alignment});
          break;
        }
        default:
          this._beforeInputTypes[type]?.(event);
      }
    }
    // --- Events
    handleEvent(event) {
      this.fireEvent(event.type, event);
    }
    fireEvent(type, detail) {
      let handlers = this._events.get(type);
      if (/^(?:focus|blur)/.test(type)) {
        const isFocused = this._root === document.activeElement;
        if (type === "focus") {
          if (!isFocused || this._isFocused) {
            return this;
          }
          this._isFocused = true;
        } else {
          if (isFocused || !this._isFocused) {
            return this;
          }
          this._isFocused = false;
        }
      }
      if (handlers) {
        const event = detail instanceof Event ? detail : new CustomEvent(type, {
          detail
        });
        handlers = handlers.slice();
        for (const handler of handlers) {
          try {
            handler.handleEvent ? handler.handleEvent(event) : handler.call(this, event);
          } catch (error) {
            error.details = 'Squire: fireEvent error. Event type: ' + type;
            didError(error);
          }
        }
      }
      return this;
    }
    addEventListener(types, fn) {
      if (!fn) {
        didError({
          name: 'Squire: addEventListener with null or undefined fn',
          message: 'Event type: ' + types
        });
        return this;
      }
      types.split(/\s+/).forEach((type) => {
        let handlers = this._events.get(type);
        let target = this._root;
        if (!handlers) {
          handlers = [];
          this._events.set(type, handlers);
          customEvents.has(type) || (type === "selectionchange" ? document : target).addEventListener(type, this, {capture:true,passive:"touchstart"===type});
        }
        handlers.push(fn);
      });
      return this;
    }
    removeEventListener(type, fn) {
      const handlers = this._events.get(type);
      if (handlers) {
        if (fn) {
          let l = handlers.length;
          while (l--) {
            if (handlers[l] === fn) {
              handlers.splice(l, 1);
            }
          }
        } else {
          handlers.length = 0;
        }
        if (!handlers.length) {
          this._events.delete(type);
          customEvents.has(type) || (type === "selectionchange" ? document : this._root).removeEventListener(type, this, true);
        }
      }
      return this;
    }
    // --- Focus
    focus() {
      this._root.focus({ preventScroll: true });
      return this;
    }
    blur() {
      this._root.blur();
      return this;
    }
    // ---
    _removeZWS() {
      if (this._mayHaveZWS) {
        removeZWS(this._root);
        this._mayHaveZWS = false;
      }
    }
    // ---
    _saveRangeToBookmark(range) {
      let [startNode, endNode] = createBookmarkNodes(),
        temp;
      insertNodeInRange(range, startNode);
      range.collapse();
      insertNodeInRange(range, endNode);
      if (startNode.compareDocumentPosition(endNode) & DOCUMENT_POSITION_PRECEDING) {
        startNode.id = endSelectionId;
        endNode.id = startSelectionId;
        temp = startNode;
        startNode = endNode;
        endNode = temp;
      }
      range.setStartAfter(startNode);
      range.setEndBefore(endNode);
    }
    _getRangeAndRemoveBookmark(range) {
      const root = this._root;
      const start = root.querySelector("#" + startSelectionId);
      const end = root.querySelector("#" + endSelectionId);
      if (start && end) {
        let startContainer = start.parentNode;
        let endContainer = end.parentNode;
        const startOffset = indexOf(startContainer.childNodes, start);
        let endOffset = indexOf(endContainer.childNodes, end);
        if (startContainer === endContainer) {
          --endOffset;
        }
        detach(start);
        detach(end);
        range = range || document.createRange();
        range.setStart(startContainer, startOffset);
        range.setEnd(endContainer, endOffset);
        mergeInlines(startContainer, range);
        if (startContainer !== endContainer) {
          mergeInlines(endContainer, range);
        }
        if (range.collapsed) {
          startContainer = range.startContainer;
          if (isTextNode(startContainer)) {
            endContainer = startContainer.childNodes[range.startOffset];
            if (!endContainer || !isTextNode(endContainer)) {
              endContainer = startContainer.childNodes[range.startOffset - 1];
            }
            if (isTextNode(endContainer)) {
              range.setStart(endContainer, 0);
              range.collapse(true);
            }
          }
        }
      }
      return range || null;
    }
    getSelection() {
      const sel = win.getSelection();
      const root = this._root;
      let range;
      if (this._isFocused && sel?.rangeCount) {
        range = sel.getRangeAt(0).cloneRange();
        const startContainer = range.startContainer;
        const endContainer = range.endContainer;
        if (startContainer && isLeaf(startContainer)) {
          range.setStartBefore(startContainer);
        }
        if (endContainer && isLeaf(endContainer)) {
          range.setEndBefore(endContainer);
        }
      }
      if (range && root.contains(range.commonAncestorContainer)) {
        this._lastSelection = range;
      } else {
        range = this._lastSelection;
        if (!document.contains(range.commonAncestorContainer)) {
          range = null;
        }
      }
      return range || createRange(root.firstChild, 0);
    }
    setSelection(range) {
      this._lastSelection = range;
      if (this._isFocused) {
        const selection = win.getSelection();
        if (selection) {
          selection.setBaseAndExtent(
            range.startContainer,
            range.startOffset,
            range.endContainer,
            range.endOffset
          );
        }
      } else {
        this._willRestoreSelection = true;
      }
      return this;
    }
    // ---
    // --- Path
    getPath() {
      return this._path;
    }
    _updatePath(range, force) {
      const anchor = range.startContainer,
        focus = range.endContainer;
      if (force || anchor !== this._pathRange.startContainer || focus !== this._pathRange.endContainer) {
        this._pathRange = range.cloneRange();
        let node = anchor === focus ? focus : null,
          newPath = (anchor && focus) ? (node ? this._getPath(focus) : "(selection)") : "";
        if (this._path !== newPath) {
          this._path = newPath;
          this.fireEvent("pathChange", {
            path: newPath,
            element: (!node || isElement(node)) ? node : node.parentElement
          });
        }
      }
      this.fireEvent(range.collapsed ? "cursor" : "select", {
        range
      });
    }
    _getPath(node) {
      const root = this._root;
      let path = "", style;
      if (node && node !== root) {
        path = this._getPath(node.parentNode, root);
        if (isElement(node)) {
          path += (path ? ">" : "") + node.nodeName;
          if (node.id) {
            path += "#" + node.id;
          }
          if (node.dir) {
            path += "[dir=" + node.dir + "]";
          }
          if (style = node.style.cssText) {
            path += "[style=" + style + "]";
          }
        }
      }
      return path;
    }
    // --- History
    _docWasChanged() {
      cache = new WeakMap();
      this._mayHaveZWS = cantFocusEmptyTextNodes;
      if (this._ignoreChange) {
        this._ignoreChange = false;
      } else {
        this.editStack.docWasChanged();
      }
    }
    /**
     * Leaves bookmark.
     */
    _recordUndoState(range, replace) {
      this.editStack.recordUndoState(range, replace);
    }
    saveUndoState(range) {
      this.editStack.saveUndoState(range);
    }
    undo() {
      this.editStack.undo();
    }
    redo() {
      this.editStack.redo();
    }
    // --- Get and set data
    getRoot() {
      return this._root;
    }
    _getRawHTML() {
      return this._root.innerHTML;
    }
    _setRawHTML(html) {
      if (html !== undefined) {
        const root = this._root;
        let node = root;
        root.innerHTML = html;
        do {
          fixCursor(node);
        } while (node = getNextBlock(node, root));
        this._ignoreChange = true;
      }
    }
    getHTML(withBookMark) {
      let html, range;
      if (withBookMark) {
        range = this.getSelection();
        this._saveRangeToBookmark(range);
      }
      html = this._getRawHTML().replace(/\u200B/g, "");
      withBookMark && this._getRangeAndRemoveBookmark(range);
      return html;
    }
    setHTML(html) {
      const root = this._root,
        frag = this._config.sanitizeToDOMFragment(html, false);
      cleanTree(frag);
      cleanupBRs(frag, root, false);
      fixContainer(frag, root);
      let node, walker = getBlockWalker(frag, root);
      while ((node = walker.nextNode()) && node !== root) {
        fixCursor(node);
      }
      this._ignoreChange = true;
      if (root.replaceChildren) {
        root.replaceChildren(frag);
      } else {
        while (root.lastChild)
          detach(root.lastChild);
        root.append(frag);
      }
      fixCursor(root);
      this.editStack.clear();
      const range = this._getRangeAndRemoveBookmark() || createRange(root.firstElementChild || root, 0);
      this.saveUndoState(range);
      this.setRange(range);
      return this;
    }
    /**
     * Insert HTML at the cursor location. If the selection is not collapsed
     * insertTreeFragmentIntoRange will delete the selection so that it is
     * replaced by the html being inserted.
     */
    insertHTML(html, isPaste) {
      let range = this.getSelection();
      if (isPaste) {
        let startFragmentIndex = html.indexOf("<!--StartFragment-->"),
          endFragmentIndex = html.lastIndexOf("<!--EndFragment-->");
        if (startFragmentIndex > -1 && endFragmentIndex > -1) {
          html = html.slice(startFragmentIndex + 20, endFragmentIndex);
        }
      }
      let frag = this._config.sanitizeToDOMFragment(html, isPaste);
      this.saveUndoState(range);
      try {
        let root = this._root, node = frag;
        addLinks(frag, frag);
        cleanTree(frag);
        cleanupBRs(frag, root, false);
        removeEmptyInlines(frag);
        frag.normalize();
        while (node = getNextBlock(node, frag)) {
          fixCursor(node);
        }
        insertTreeFragmentIntoRange(range, frag, root);
        range.collapse();
        moveRangeBoundaryOutOf(range, "A", root);
        this._ensureBottomLine();
        this.setRange(range);
        isPaste && this.focus();
      } catch (error) {
        didError(error);
      }
      return this;
    }
    insertElement(el, range) {
      range = range || this.getSelection();
      range.collapse(true);
      if (isInline(el)) {
        insertNodeInRange(range, el);
        range.setStartAfter(el);
      } else {
        const root = this._root;
        let splitNode = getStartBlockOfRange(range, root) || root;
        let nodeAfterSplit;
        while (splitNode !== root && !splitNode.nextSibling) {
          splitNode = splitNode.parentNode;
        }
        if (splitNode !== root) {
          const parent = splitNode.parentNode;
          nodeAfterSplit = split(parent, splitNode.nextSibling, root, root);
        }
        if (nodeAfterSplit) {
          nodeAfterSplit.before(el);
        } else {
          root.append(el);
          nodeAfterSplit = this.createDefaultBlock();
          root.append(nodeAfterSplit);
        }
        range.setStart(nodeAfterSplit, 0);
        range.setEnd(nodeAfterSplit, 0);
        moveRangeBoundariesDownTree(range);
      }
      this.focus();
      this.setSelection(range);
      this._updatePath(range);
      return this;
    }
    insertImage(src, attributes) {
      const img = createElement("IMG", mergeObjects({
        src: src
      }, attributes, true));
      this.insertElement(img);
      return img;
    }
    insertPlainText(plainText, isPaste) {
      const range = this.getSelection();
      if (range.collapsed && getClosest(range.startContainer, this._root, "PRE")) {
        let node = range.startContainer;
        let offset = range.startOffset;
        let text;
        if (!isTextNode(node)) {
          text = document.createTextNode("");
          node?.childNodes[offset].before(text);
          node = text;
          offset = 0;
        }
        node.insertData(offset, plainText);
        range.setStart(node, offset + plainText.length);
        range.collapse(true);
        this.setSelection(range);
        return this;
      }
      const lines = plainText.split(/\r?\n/),
        closeBlock = "</" + blockTag + ">",
        openBlock = "<" + blockTag + ">";
      lines.forEach((line, i) => {
        line = escapeHTML(line).replace(/ (?=(?: |$))/g, NBSP);
        lines[i] = i ? openBlock + (line || "<BR>") + closeBlock : line;
      });
      return this.insertHTML(lines.join(""), isPaste);
    }
    // --- Inline formatting
    /**
     * Extracts the font-family and font-size (if any) of the element
     * holding the cursor. If there's a selection, returns an empty object.
     */
    getFontInfo(range) {
      const fontInfo = {
        color: void 0,
        backgroundColor: void 0,
        family: void 0,
        size: void 0
      };
      range = range || this.getSelection();
      let seenAttributes = 0;
      let element = range.commonAncestorContainer, style, attr;
      if (range.collapsed || isTextNode(element)) {
        if (isTextNode(element)) {
          element = element.parentNode;
        }
        while (seenAttributes < 4 && element) {
          if (style = element.style) {
            if (!fontInfo.color && (attr = style.color)) {
              fontInfo.color = attr;
              ++seenAttributes;
            }
            if (!fontInfo.backgroundColor && (attr = style.backgroundColor)) {
              fontInfo.backgroundColor = attr;
              ++seenAttributes;
            }
            if (!fontInfo.family && (attr = style.fontFamily)) {
              fontInfo.family = attr;
              ++seenAttributes;
            }
            if (!fontInfo.size && (attr = style.fontSize)) {
              fontInfo.size = attr;
              ++seenAttributes;
            }
          }
          element = element.parentNode;
        }
      }
      return fontInfo;
    }
    /**
     * Looks for matching tag and attributes, so won't work if <strong>
     * instead of <b> etc.
     */
    hasFormat(tag, attributes, range) {
      tag = tag.toUpperCase();
      range = range || this.getSelection();
      if (!range.collapsed && isTextNode(range.startContainer) && range.startOffset === range.startContainer.length && range.startContainer.nextSibling) {
        range.setStartBefore(range.startContainer.nextSibling);
      }
      if (!range.collapsed && isTextNode(range.endContainer) && range.endOffset === 0 && range.endContainer.previousSibling) {
        range.setEndAfter(range.endContainer.previousSibling);
      }
      const root = this._root;
      const common = range.commonAncestorContainer;
      if (getNearest(common, root, tag, attributes)) {
        return true;
      }
      if (isTextNode(common)) {
        return false;
      }
      const walker = createTreeWalker(common, SHOW_TEXT, (node2) => isNodeContainedInRange(range, node2));
      let seenNode = false;
      let node;
      while (node = walker.nextNode()) {
        if (!getNearest(node, root, tag, attributes)) {
          return false;
        }
        seenNode = true;
      }
      return seenNode;
    }
    changeFormat(add, remove, range, partial) {
      range = range || this.getSelection();
      this.saveUndoState(range);
      if (remove) {
        range = this._removeFormat(
          remove.tag.toUpperCase(),
          remove.attributes || {},
          range,
          partial
        );
      }
      if (add) {
        range = this._addFormat(
          add.tag.toUpperCase(),
          add.attributes || {},
          range
        );
      }
      this.setRange(range);
      return this.focus();
    }
    _addFormat(tag, attributes, range) {
      const root = this._root;
      let node;
      if (range.collapsed) {
        const el = fixCursor(createElement(tag, attributes));
        insertNodeInRange(range, el);
        range.setStart(el.firstChild, el.firstChild.length);
        range.collapse(true);
        let block = el;
        while (isInline(block)) {
          block = block.parentNode;
        }
        removeZWS(block, el);
      } else {
        const filter = (node) => (isTextNode(node) || isBrElement(node) || node.nodeName === "IMG") && isNodeContainedInRange(range, node);
        const walker = createTreeWalker(
          range.commonAncestorContainer,
          SHOW_ELEMENT_OR_TEXT,
          filter
        );
        let { startContainer, startOffset, endContainer, endOffset } = range;
        walker.currentNode = startContainer;
        if (!isElement(startContainer) && !isTextNode(startContainer) || !filter(startContainer)) {
          startContainer = walker.nextNode();
          startOffset = 0;
        }
        if (startContainer) {
          do {
            node = walker.currentNode;
            if (!getNearest(node, root, tag, attributes)) {
              if (node === endContainer && node.length > endOffset) {
                node.splitText(endOffset);
              }
              if (node === startContainer && startOffset) {
                node = node.splitText(startOffset);
                if (endContainer === startContainer) {
                  endContainer = node;
                  endOffset -= startOffset;
                }
                startContainer = node;
                startOffset = 0;
              }
              const el = createElement(tag, attributes);
              replaceWith(node, el);
              el.append(node);
            }
          } while (walker.nextNode());
          if (!isTextNode(endContainer)) {
            if (isTextNode(node)) {
              endContainer = node;
              endOffset = node.length;
            } else {
              endContainer = node.parentNode;
              endOffset = 1;
            }
          }
          range = createRange(
            startContainer,
            startOffset,
            endContainer,
            endOffset
          );
        }
      }
      return range;
    }
    _removeFormat(tag, attributes, range, partial) {
      this._saveRangeToBookmark(range);
      let fixer;
      if (range.collapsed) {
        this._mayHaveZWS = cantFocusEmptyTextNodes;
        fixer = document.createTextNode(cantFocusEmptyTextNodes ? ZWS : "");
        insertNodeInRange(range, fixer);
      }
      let root = range.commonAncestorContainer;
      while (isInline(root)) {
        root = root.parentNode;
      }
      const { startContainer, startOffset, endContainer, endOffset } = range;
      const toWrap = [];
      const examineNode = (node, exemplar) => {
        if (isNodeContainedInRange(range, node, false)) {
          return;
        }
        let isText = isTextNode(node);
        let child;
        let next;
        if (!isNodeContainedInRange(range, node)) {
          if (node.nodeName !== "INPUT" && (!isText || node.data)) {
            toWrap.push([exemplar, node]);
          }
          return;
        }
        if (isText) {
          if (node === endContainer && endOffset !== node.length) {
            toWrap.push([exemplar, node.splitText(endOffset)]);
          }
          if (node === startContainer && startOffset) {
            node.splitText(startOffset);
            toWrap.push([exemplar, node]);
          }
        } else {
          for (child = node.firstChild; child; child = next) {
            next = child.nextSibling;
            examineNode(child, exemplar);
          }
        }
      };
      const formatTags = Array.prototype.filter.call(
        root.getElementsByTagName(tag),
        (el) => isNodeContainedInRange(range, el, true) && hasTagAttributes(el, tag, attributes)
      );
      partial || formatTags.forEach((node) => examineNode(node, node));
      toWrap.forEach(([el, node]) => {
        el = el.cloneNode(false);
        replaceWith(node, el);
        el.append(node);
      });
      formatTags.forEach((el) => replaceWith(el, empty(el)));
      if (cantFocusEmptyTextNodes && fixer) {
        fixer = fixer.parentNode;
        let block = fixer;
        while (block && isInline(block)) {
          block = block.parentNode;
        }
        if (block) {
          removeZWS(block, fixer);
        }
      }
      this._getRangeAndRemoveBookmark(range);
      fixer && range.collapse();
      mergeInlines(root, range);
      return range;
    }
    // ---
    bold() {
      this.toggleTag("B");
    }
    italic() {
      this.toggleTag("I");
    }
    underline() {
      this.toggleTag("U");
    }
    strikethrough() {
      this.toggleTag("S");
    }
    subscript() {
      this.toggleTag("SUB", "SUP");
    }
    superscript() {
      this.toggleTag("SUP", "SUB");
    }
    // ---
    makeLink(url, attributes) {
      const range = this.getSelection();
      if (range.collapsed) {
        insertNodeInRange(
          range,
          document.createTextNode(url.replace(/^[^:]*:\/*/, ""))
        );
      }
      attributes = mergeObjects(
        mergeObjects({
          href: url
        }, attributes, true),
        null,
        false
      );
      return this.changeFormat(
        {
          tag: "A",
          attributes
        },
        {
          tag: "A"
        },
        range
      );
    }
    removeLink() {
      return this.changeFormat(
        null,
        {
          tag: "A"
        },
        this.getSelection(),
        true
      );
    }
    // --- Block formatting
    _ensureBottomLine() {
      const root = this._root;
      const last = root.lastElementChild;
      if (!last || last.nodeName !== blockTag || !isBlock(last)) {
        root.append(this.createDefaultBlock());
      }
    }
    createDefaultBlock(children) {
      return fixCursor(
        createElement(blockTag, null, children)
      );
    }
    splitBlock(lineBreakOnly, range) {
      range = range || this.getSelection();
      const root = this._root;
      let block;
      let parent;
      let node;
      let nodeAfterSplit;
      this.editStack.inUndoState && this._docWasChanged();
      this._recordUndoState(range);
      this._removeZWS();
      this._getRangeAndRemoveBookmark(range);
      if (!range.collapsed) {
        deleteContentsOfRange(range, root);
      }
      if (this._config.addLinks) {
        moveRangeBoundariesDownTree(range);
        setTimeout(() => {
          addLinks(range.startContainer, root);
        }, 0);
      }
      block = getStartBlockOfRange(range, root);
      if (block && (parent = getClosest(block, root, "PRE"))) {
        moveRangeBoundariesDownTree(range);
        node = range.startContainer;
        const offset2 = range.startOffset;
        if (!isTextNode(node)) {
          node = document.createTextNode("");
          parent.insertBefore(node, parent.firstChild);
        }
        if (!lineBreakOnly && isTextNode(node) && (node.data.charAt(offset2 - 1) === "\n" || rangeDoesStartAtBlockBoundary(range, root)) && (node.data.charAt(offset2) === "\n" || rangeDoesEndAtBlockBoundary(range, root))) {
          node.deleteData(offset2 && offset2 - 1, offset2 ? 2 : 1);
          nodeAfterSplit = split(
            node,
            offset2 && offset2 - 1,
            root,
            root
          );
          node = nodeAfterSplit.previousSibling;
          if (!node.textContent) {
            detach(node);
          }
          node = this.createDefaultBlock();
          nodeAfterSplit.before(node);
          if (!nodeAfterSplit.textContent) {
            detach(nodeAfterSplit);
          }
          range.setStart(node, 0);
        } else {
          node.insertData(offset2, "\n");
          fixCursor(parent);
          if (node.length === offset2 + 1) {
            range.setStartAfter(node);
          } else {
            range.setStart(node, offset2 + 1);
          }
        }
        range.collapse(true);
        this.setRange(range);
        this._docWasChanged();
        return;
      }
      if (!block || lineBreakOnly || /^T[HD]$/.test(block.nodeName)) {
        moveRangeBoundaryOutOf(range, "A", root);
        insertNodeInRange(range, createElement("BR"));
        range.collapse();
        this.setRange(range);
        return;
      }
      block = getClosest(block, root, "LI") || block;
      if (isEmptyBlock(block) && (parent = getClosest(block, root, "UL,OL,BLOCKQUOTE"))) {
        return "BLOCKQUOTE" === parent.nodeName
          ? this.modifyBlocks((/* frag */) => this.createDefaultBlock(createBookmarkNodes()), range)
          : this.decreaseListLevel(range);
      }
      node = range.startContainer;
      const offset = range.startOffset;
      let splitTag = tagAfterSplit[block.nodeName] || blockTag;
      nodeAfterSplit = split(
        node,
        offset,
        block.parentNode,
        root
      );
      if (!hasTagAttributes(nodeAfterSplit, splitTag)) {
        block = createElement(splitTag);
        if (nodeAfterSplit.dir) {
          block.dir = nodeAfterSplit.dir;
        }
        replaceWith(nodeAfterSplit, block);
        block.append(empty(nodeAfterSplit));
        nodeAfterSplit = block;
      }
      removeZWS(block);
      removeEmptyInlines(block);
      fixCursor(block);
      while (isElement(nodeAfterSplit)) {
        let child = nodeAfterSplit.firstChild;
        let next;
        if (nodeAfterSplit.nodeName === "A" && (!nodeAfterSplit.textContent || nodeAfterSplit.textContent === ZWS)) {
          child = document.createTextNode("");
          replaceWith(nodeAfterSplit, child);
          nodeAfterSplit = child;
          break;
        }
        while (isTextNode(child) && !child.data) {
          next = child.nextSibling;
          if (!next || isBrElement(next)) {
            break;
          }
          detach(child);
          child = next;
        }
        if (!child || isBrElement(child) || isTextNode(child)) {
          break;
        }
        nodeAfterSplit = child;
      }
      range = createRange(nodeAfterSplit, 0);
      this.setRange(range);
    }
    modifyBlocks(modify, range) {
      range = range || this.getSelection();
      this._recordUndoState(range, true);
      const root = this._root;
      expandRangeToBlockBoundaries(range, root);
      moveRangeBoundariesUpTree(range, root, root, root);
      const frag = extractContentsOfRange(range, root, root);
      insertNodeInRange(range, modify.call(this, frag));
      if (range.endOffset < range.endContainer.childNodes.length) {
        mergeContainers(
          range.endContainer.childNodes[range.endOffset],
          root
        );
      }
      mergeContainers(
        range.startContainer.childNodes[range.startOffset],
        root
      );
      this._getRangeAndRemoveBookmark(range);
      this.setRange(range);
      return this;
    }
    // ---
    setTextDirection(direction) {
      return this.modifyBlocks(frag => setDirection(this, frag, direction)).focus();
    }
    increaseListLevel(range) {
      range = range || this.getSelection();
      const root = this._root;
      const listSelection = getListSelection(range, root);
      if (listSelection) {
        let [list, startLi, endLi] = listSelection;
        if (startLi && startLi !== list.firstChild) {
          this._recordUndoState(range, true);
          const type = list.nodeName;
          let newParent = startLi.previousSibling;
          let next;
          if (newParent.nodeName !== type) {
            newParent = createElement(type);
            startLi.before(newParent);
          }
          do {
            next = startLi === endLi ? null : startLi.nextSibling;
            newParent.append(startLi);
          } while (startLi = next);
          next = newParent.nextSibling;
          next && mergeContainers(next, root);
          this._getRangeAndRemoveBookmark(range);
          this.setRange(range);
        }
      }
      return this.focus();
    }
    decreaseListLevel(range) {
      range = range || this.getSelection();
      const root = this._root;
      const listSelection = getListSelection(range, root);
      if (listSelection) {
        let list = listSelection[0];
        let startLi = listSelection[1] || list.firstChild;
        let endLi = listSelection[2] || list.lastChild;
        let next, insertBefore;
        this._recordUndoState(range, true);
        if (startLi) {
          let newParent = list.parentNode;
          insertBefore = !endLi.nextSibling ?
            list.nextSibling :
            split(list, endLi.nextSibling, newParent, root);
          if (newParent !== root && newParent.nodeName === "LI") {
            newParent = newParent.parentNode;
            while (insertBefore) {
              next = insertBefore.nextSibling;
              endLi.append(insertBefore);
              insertBefore = next;
            }
            insertBefore = list.parentNode.nextSibling;
          }
          const makeNotList = !/^[OU]L$/.test(newParent.nodeName);
          do {
            next = startLi === endLi ? null : startLi.nextSibling;
            startLi.remove();
            if (makeNotList && startLi.nodeName === "LI") {
              startLi = this.createDefaultBlock([empty(startLi)]);
            }
            newParent.insertBefore(startLi, insertBefore);
          } while (startLi = next);
        }
        list.firstChild || detach(list);
        insertBefore && mergeContainers(insertBefore, root);
        this._getRangeAndRemoveBookmark(range);
        this.setRange(range);
      }
      return this.focus();
    }
    _makeList(frag, type) {
      let walker = getBlockWalker(frag, this._root),
        node, tag, prev, newLi;
      while (node = walker.nextNode()) {
        if (node.parentNode.nodeName === "LI") {
          node = node.parentNode;
          walker.currentNode = node.lastChild;
        }
        if (node.nodeName !== "LI") {
          newLi = createElement("LI");
          if (node.dir) {
            newLi.dir = node.dir;
          }
          if ((prev = node.previousSibling) && prev.nodeName === type) {
            prev.append(newLi);
            detach(node);
          } else {
            replaceWith(node, createElement(type, null, [newLi]));
          }
          newLi.append(empty(node));
          walker.currentNode = newLi;
        } else {
          node = node.parentNode;
          tag = node.nodeName;
          if (tag !== type && listNodeNames.has(tag)) {
            replaceWith(node,
              createElement(type, null, [empty(node)])
            );
          }
        }
      }
      return frag;
    }
    makeUnorderedList() {
      return this.modifyBlocks((frag) => this._makeList(frag, "UL")).focus();
    }
    makeOrderedList() {
      return this.modifyBlocks((frag) => this._makeList(frag, "OL")).focus();
    }
    removeList() {
      return this.modifyBlocks((frag) => {
        const root = this._root;
        frag.querySelectorAll("LI").forEach((item) => {
          if (isBlock(item)) {
            replaceWith(item, this.createDefaultBlock([empty(item)]));
          } else {
            fixContainer(item, root);
            replaceWith(item, empty(item));
          }
        });
        frag.querySelectorAll("UL, OL").forEach((list) => {
          const listFrag = empty(list);
          fixContainer(listFrag, root);
          replaceWith(list, listFrag);
        });
        return frag;
      }).focus();
    }
    // ---
    increaseQuoteLevel(range) {
      return this.modifyBlocks(
        (frag) => createElement(
          "BLOCKQUOTE",
          null,
          [frag]
        ),
        range
      ).focus();
    }
    decreaseQuoteLevel(range) {
      return this.modifyBlocks((frag) => {
        Array.prototype.filter.call(
          frag.querySelectorAll("blockquote"),
          (el) => !getClosest(el.parentNode, frag, "BLOCKQUOTE")
        ).forEach(
          (el) => replaceWith(el, empty(el))
        );
        return frag;
      }, range).focus();
    }
    // ---
    code() {
      const range = this.getSelection();
      if (range.collapsed || isContainer(range.commonAncestorContainer)) {
        return this.modifyBlocks((frag) => {
          const root = this._root;
          const output = document.createDocumentFragment();
          let walker = getBlockWalker(frag, root);
          let node;
          while (node = walker.nextNode()) {
            node.querySelectorAll("BR").forEach(br => {
              if (!isLineBreak(br, false)) {
                detach(br);
              } else {
                replaceWith(br, document.createTextNode("\n"));
              }
            });
            node.querySelectorAll("CODE").forEach(el => detach(el));
            if (output.childNodes.length) {
              output.append(document.createTextNode("\n"));
            }
            output.append(empty(node));
          }
          walker = createTreeWalker(output, SHOW_TEXT);
          while (node = walker.nextNode()) {
            node.data = node.data.replace(NBSP, " "); // nbsp -> sp
          }
          output.normalize();
          return fixCursor(
            createElement("PRE", null, [
              output
            ])
          );
        }, range).focus();
      }
      return this.changeFormat({ tag: "CODE" }, null, range);
    }
    removeCode() {
      const range = this.getSelection();
      const ancestor = range.commonAncestorContainer;
      const inPre = getClosest(ancestor, this._root, "PRE");
      if (inPre) {
        return this.modifyBlocks((frag) => {
          const root = this._root;
          const pres = frag.querySelectorAll("PRE");
          let l = pres.length;
          let pre, walker, node, value, contents, index;
          while (l--) {
            pre = pres[l];
            walker = createTreeWalker(pre, SHOW_TEXT);
            while (node = walker.nextNode()) {
              value = node.data;
              value = value.replace(/ (?=)/g, NBSP); // sp -> nbsp
              contents = document.createDocumentFragment();
              while ((index = value.indexOf("\n")) > -1) {
                contents.append(
                  document.createTextNode(value.slice(0, index))
                );
                contents.append(createElement("BR"));
                value = value.slice(index + 1);
              }
              node.before(contents);
              node.data = value;
            }
            fixContainer(pre, root);
            replaceWith(pre, empty(pre));
          }
          return frag;
        }, range).focus();
      }
      return this.changeFormat(null, { tag: "CODE" }, range);
    }
    toggleCode() {
      return (this.hasFormat("PRE") || this.hasFormat("CODE")) ? this.removeCode() : this.code();
    }
    // SnappyMail
    changeIndentationLevel(direction) {
      let parent = this.getSelectionClosest("UL,OL,BLOCKQUOTE");
      if (parent || "increase" === direction) {
        direction += (!parent || "BLOCKQUOTE" === parent.nodeName) ? "Quote" : "List";
        return this[direction + "Level"]();
      }
    }
    getSelectionClosest(selector) {
      return getClosest(this.getSelection().commonAncestorContainer, this._root, selector);
    }
    setAttribute(name, value) {
      let range = this.getSelection();
      let start = range?.startContainer || {};
      let end = range?.endContainer || {};
      if ("dir" == name || (isTextNode(start) && 0 === range.startOffset && start === end && end.length === range.endOffset)) {
        this._recordUndoState(range);
        setAttributes(start.parentNode, { [name]: value });
        this._docWasChanged();
      } else if (null == value) {
        this._recordUndoState(range);
        let node = getClosest(range.commonAncestorContainer, this._root, "*");
        range.collapsed ? setAttributes(node, { [name]: value }) : node.querySelectorAll("*").forEach((el) => setAttributes(el, { [name]: value }));
        this._docWasChanged();
      } else {
        this.changeFormat({
          tag: "SPAN",
          attributes: { [name]: value }
        }, null, range);
      }
      return this.focus();
    }
    setStyle(style) {
      this.setAttribute("style", style);
    }
    toggleTag(name, remove) {
      let range = this.getSelection();
      if (this.hasFormat(name, null, range)) {
        this.changeFormat(null, { tag: name }, range);
      } else {
        this.changeFormat({ tag: name }, remove ? { tag: remove } : null, range);
      }
    }
    setRange(range) {
      this.setSelection(range);
      this._updatePath(range, true);
    }

    setConfig(config) {
      this._config = mergeObjects({
        addLinks: true
      }, config, true);
      return this;
    }
  }

  // source/Legacy.ts
  win.Squire = Squire;
})();
