# AngularJS

## 1 AngularJS 扩展了 HTML

AngularJS 通过 **ng-directives** 扩展了 HTML。常见的使用场景：

- **ng-app** 指令定义一个 AngularJS 应用程序。

- **ng-model** 指令把元素值（比如输入域的值）绑定到应用程序。

- **ng-bind** 指令把应用程序数据绑定到 HTML 视图。

- 你可以使用 **.directive** 函数来添加自定义的指令。

- **ng-repeat** 指令对于集合中（数组中）的每个项会 **克隆一次 HTML 元素**。



AngularJS 作用：

- AngularJS 把应用程序数据绑定到 HTML 元素。
- AngularJS 可以克隆和重复 HTML 元素。
- AngularJS 可以隐藏和显示 HTML 元素。
- AngularJS 可以在 HTML 元素"背后"添加代码。
- AngularJS 支持输入验证。



**demo**

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>
</head>
<body>
 
<div ng-app="">
    <p>名字 : <input type="text" ng-model="name"></p>
    <h1>Hello {{name}}</h1>
    <p ng-bind="name"></p>
</div>
 
</body>
</html>
```



当网页加载完毕，AngularJS 自动开启。

**ng-app** 指令告诉 AngularJS，<div> 元素是 AngularJS **应用程序** 的"所有者"。

**ng-model** 指令把输入域的值绑定到应用程序变量 **name**。

**ng-bind** 指令把应用程序变量 name 绑定到某个段落的 innerHTML。



## 2 AngularJS 表达式

AngularJS 表达式写在双大括号内：**{{ expression }}**。

====>AngularJS 表达式把数据绑定到 HTML，这与 **ng-bind** 指令有异曲同工之妙。

AngularJS 将在表达式书写的位置"输出"数据。

**AngularJS 表达式** 很像 **JavaScript 表达式**：它们可以包含文字、运算符和变量。

实例 {{ 5 + 5 }} 或 {{ firstName + " " + lastName }}

# 3 AngularJS ng-model 指令

ng-model 指令用于绑定应用程序数据到 HTML 控制器(input, select, textarea)的值。

`ng-model` 指令可以将输入域的值与 AngularJS 创建的变量绑定。

AngularJS 应用程序由 **ng-app** 定义。应用程序在 <div> 内运行。

**ng-controller="myCtrl"** 属性是一个 AngularJS 指令。用于定义一个控制器。

**myCtrl** 函数是一个 JavaScript 函数。

**ng-model** 指令绑定输入域到控制器的属性（firstName 和 lastName）。



## 4 AngularJS 指令

本教程用到的 AngularJS 指令 :

| 指令                                                         | 描述                                                         |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| [ng-app](https://www.runoob.com/angularjs/ng-ng-app.html)    | 定义应用程序的根元素。                                       |
| [ng-bind](https://www.runoob.com/angularjs/ng-ng-bind.html)  | 绑定 HTML 元素到应用程序数据                                 |
| [ng-bind-html](https://www.runoob.com/angularjs/ng-ng-bind-html.html) | 绑定 HTML 元素的 innerHTML 到应用程序数据，并移除 HTML 字符串中危险字符 |
| [ng-bind-template](https://www.runoob.com/angularjs/ng-ng-bind-template.html) | 规定要使用模板替换的文本内容                                 |
| [ng-blur](https://www.runoob.com/angularjs/ng-ng-blur.html)  | 规定 blur 事件的行为                                         |
| [ng-change](https://www.runoob.com/angularjs/ng-ng-change.html) | 规定在内容改变时要执行的表达式                               |
| [ng-checked](https://www.runoob.com/angularjs/ng-ng-checked.html) | 规定元素是否被选中                                           |
| [ng-class](https://www.runoob.com/angularjs/ng-ng-class.html) | 指定 HTML 元素使用的 CSS 类                                  |
| [ng-class-even](https://www.runoob.com/angularjs/ng-ng-class-even.html) | 类似 ng-class，但只在偶数行起作用                            |
| [ng-class-odd](https://www.runoob.com/angularjs/ng-ng-class-odd.html) | 类似 ng-class，但只在奇数行起作用                            |
| [ng-click](https://www.runoob.com/angularjs/ng-ng-click.html) | 定义元素被点击时的行为                                       |
| [ng-cloak](https://www.runoob.com/angularjs/ng-ng-cloak.html) | 在应用正要加载时防止其闪烁                                   |
| [ng-controller](https://www.runoob.com/angularjs/ng-ng-controller.html) | 定义应用的控制器对象                                         |
| [ng-copy](https://www.runoob.com/angularjs/ng-ng-copy.html)  | 规定拷贝事件的行为                                           |
| [ng-csp](https://www.runoob.com/angularjs/ng-ng-csp.html)    | 修改内容的安全策略                                           |
| [ng-cut](https://www.runoob.com/angularjs/ng-ng-cut.html)    | 规定剪切事件的行为                                           |
| [ng-dblclick](https://www.runoob.com/angularjs/ng-ng-dblclick.html) | 规定双击事件的行为                                           |
| [ng-disabled](https://www.runoob.com/angularjs/ng-ng-disabled.html) | 规定一个元素是否被禁用                                       |
| [ng-focus](https://www.runoob.com/angularjs/ng-ng-focus.html) | 规定聚焦事件的行为                                           |
| ng-form                                                      | 指定 HTML 表单继承控制器表单                                 |
| [ng-hide](https://www.runoob.com/angularjs/ng-ng-hide.html)  | 隐藏或显示 HTML 元素                                         |
| [ng-href](https://www.runoob.com/angularjs/ng-ng-href.html)  | 为 the <a> 元素指定链接                                      |
| [ng-if](https://www.runoob.com/angularjs/ng-ng-if.html)      | 如果条件为 false 移除 HTML 元素                              |
| [ng-include](https://www.runoob.com/angularjs/ng-ng-include.html) | 在应用中包含 HTML 文件                                       |
| [ng-init](https://www.runoob.com/angularjs/ng-ng-init.html)  | 定义应用的初始化值                                           |
| ng-jq                                                        | 定义应用必须使用到的库，如：jQuery                           |
| [ng-keydown](https://www.runoob.com/angularjs/ng-ng-keydown.html) | 规定按下按键事件的行为                                       |
| [ng-keypress](https://www.runoob.com/angularjs/ng-ng-keypress.html) | 规定按下按键事件的行为                                       |
| [ng-keyup](https://www.runoob.com/angularjs/ng-ng-keyup.html) | 规定松开按键事件的行为                                       |
| [ng-list](https://www.runoob.com/angularjs/ng-ng-list.html)  | 将文本转换为列表 (数组)                                      |
| [ng-model](https://www.runoob.com/angularjs/ng-ng-model.html) | 绑定 HTML 控制器的值到应用数据                               |
| [ng-model-options](https://www.runoob.com/angularjs/ng-ng-model-options.html) | 规定如何更新模型                                             |
| [ng-mousedown](https://www.runoob.com/angularjs/ng-ng-mousedown.html) | 规定按下鼠标按键时的行为                                     |
| [ng-mouseenter](https://www.runoob.com/angularjs/ng-ng-mouseenter.html) | 规定鼠标指针穿过元素时的行为                                 |
| [ng-mouseleave](https://www.runoob.com/angularjs/ng-ng-mouseleave.html) | 规定鼠标指针离开元素时的行为                                 |
| [ng-mousemove](https://www.runoob.com/angularjs/ng-ng-mousemove.html) | 规定鼠标指针在指定的元素中移动时的行为                       |
| [ng-mouseover](https://www.runoob.com/angularjs/ng-ng-mouseover.html) | 规定鼠标指针位于元素上方时的行为                             |
| [ng-mouseup](https://www.runoob.com/angularjs/ng-ng-mouseup.html) | 规定当在元素上松开鼠标按钮时的行为                           |
| [ng-non-bindable](https://www.runoob.com/angularjs/ng-ng-non-bindable.html) | 规定元素或子元素不能绑定数据                                 |
| [ng-open](https://www.runoob.com/angularjs/ng-ng-open.html)  | 指定元素的 open 属性                                         |
| [ng-options](https://www.runoob.com/angularjs/ng-ng-options.html) | 在 <select> 列表中指定 <options>                             |
| [ng-paste](https://www.runoob.com/angularjs/ng-ng-paste.html) | 规定粘贴事件的行为                                           |
| ng-pluralize                                                 | 根据本地化规则显示信息                                       |
| [ng-readonly](https://www.runoob.com/angularjs/ng-ng-readonly.html) | 指定元素的 readonly 属性                                     |
| [ng-repeat](https://www.runoob.com/angularjs/ng-ng-repeat.html) | 定义集合中每项数据的模板                                     |
| [ng-selected](https://www.runoob.com/angularjs/ng-ng-selected.html) | 指定元素的 selected 属性                                     |
| [ng-show](https://www.runoob.com/angularjs/ng-ng-show.html)  | 显示或隐藏 HTML 元素                                         |
| [ng-src](https://www.runoob.com/angularjs/ng-ng-src.html)    | 指定 <img> 元素的 src 属性                                   |
| [ng-srcset](https://www.runoob.com/angularjs/ng-ng-srcset.html) | 指定 <img> 元素的 srcset 属性                                |
| [ng-style](https://www.runoob.com/angularjs/ng-ng-style.html) | 指定元素的 style 属性                                        |
| [ng-submit](https://www.runoob.com/angularjs/ng-ng-submit.html) | 规定 onsubmit 事件发生时执行的表达式                         |
| [ng-switch](https://www.runoob.com/angularjs/ng-ng-switch.html) | 规定显示或隐藏子元素的条件                                   |
| ng-transclude                                                | 规定填充的目标位置                                           |
| [ng-value](https://www.runoob.com/angularjs/ng-ng-value.html) | 规定 input 元素的值                                          |

## 5 AngularJS 事件

AngularJS 支持以下事件:

- ng-click
- ng-dbl-click
- ng-mousedown
- ng-mouseenter
- ng-mouseleave
- ng-mousemove
- ng-keydown
- ng-keyup
- ng-keypress
- ng-change

事件解析： [Angular 事件](https://www.runoob.com/angularjs/angularjs-html-events.html)。

## 6 AngularJS 验证属性

- $dirty
- $invalid
- $error

验证解析：[Angular 验证](https://www.runoob.com/angularjs/angularjs-validation.html)。

## 7 AngularJS 全局 API

### 转换

| API                 | 描述                 |
| :------------------ | :------------------- |
| angular.lowercase() | 将字符串转换为小写   |
| angular.uppercase() | 将字符串转换为大写   |
| angular.copy()      | 数组或对象深度拷贝   |
| angular.forEach()   | 对象或数组的迭代函数 |

### 比较

| API                   | 描述                           |
| :-------------------- | :----------------------------- |
| angular.isArray()     | 如果引用的是数组返回 true      |
| angular.isDate()      | 如果引用的是日期返回 true      |
| angular.isDefined()   | 如果引用的已定义返回 true      |
| angular.isElement()   | 如果引用的是 DOM 元素返回 true |
| angular.isFunction()  | 如果引用的是函数返回 true      |
| angular.isNumber()    | 如果引用的是数字返回 true      |
| angular.isObject()    | 如果引用的是对象返回 true      |
| angular.isString()    | 如果引用的是字符串返回 true    |
| angular.isUndefined() | 如果引用的未定义返回 true      |
| angular.equals()      | 如果两个对象相等返回 true      |

### JSON

| API                | 描述                 |
| :----------------- | :------------------- |
| angular.fromJson() | 反序列化 JSON 字符串 |
| angular.toJson()   | 序列化 JSON 字符串   |

### 基础

| API                 | 描述                                                         |
| :------------------ | :----------------------------------------------------------- |
| angular.bootstrap() | 手动启动 AngularJS                                           |
| angular.element()   | 包裹着一部分DOM element或者是HTML字符串，把它作为一个jQuery元素来处理。 |
| angular.module()    | 创建，注册或检索 AngularJS 模块                              |