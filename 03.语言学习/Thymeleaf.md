# Thymeleaf 模板安全分析

## 1、Thymeleaf简介

Thymeleaf是用于Web和独立环境的现代服务器端Java模板引擎。类似与python web开发中的jinja模板引擎。顺便说一句，Thymeleaf是spring boot的推荐引擎。

### 为啥用 Thymeleaf

Thymeleaf是SpringBoot中的一个模版引擎，个人认为有点类似于Python中的Jinja2，负责渲染前端页面。

之前写JavaWeb和SSM的时候，前端页面可能会用JSP写，但是因为之前项目都是war包部署，而SpringBoot都是jar包且内嵌tomcat，所以是不支持解析jsp文件的。

但是如果是编写纯静态的html就很不方便，那么这时候就需要一个模版引擎类似于Jinja2可以通过表达式帮我们把动态的变量渲染到前端页面，我们只需要写一个template即可。这也就是SpringBoot为什么推荐要使用Thymeleaf处理前端页面了。



## 2、 基础知识 

Spring Boot 本身就 Spring MVC 的简化版本。是在 Spring MVC 的基础上实现了自动配置，简化了开发人员开发过程。Spring MVC 是通过一个叫 DispatcherServlet 前端控制器的来拦截请求的。而在 Spring Boot 中 使用自动配置把 DispatcherServlet 前端控制器自动配置到框架中。

例如，我们来解析 /users 这个请求

![](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221030112222017.png)

1. DispatcherServlet 前端控制器拦截请求 /users
2. servlet 决定使用哪个 handler 处理
3. Spring 检测哪个控制器匹配 /users，Spring 从 @RquestMapping 中查找出需要的信息
4. Spring 找到正确的 Controller 方法后，开始执行 Controller 方法
5. 返回 users 对象列表
6. 根据与客户端交互需要返回 Json 或者 Xml 格式

#### spring boot 相关注解

- @Controller 处理 Http 请求

- @RestController @Controller 的衍生注解

  -- @RestController 是 @Controller 和 @ResponseBody 两个注解的结合体。

- @RequestMapping 路由请求 可以设置各种操作方法

- @GetMapping GET 方法的路由

- @PostMapping POST 方法的路由

- @PutMapping PUT 方法的路由

- @DeleteMapping DELETE 方法的路由

- @PathVariable 处理请求 url 路径中的参数 /user/{id}

- @RequestParam 处理问号后面的参数

- @RequestBody 请求参数以json格式提交

- @ResponseBody 返回 json 格式

#### Controller注解

@Controller 一般应用在有返回界面的应用场景下.例如，管理后台使用了 thymeleaf 作为模板开发，需要从后台直接返回 Model 对象到前台，那么这时候就需要使用 @Controller 来注解。

@Controller 包括了 @RestController。@RestController 是 Spring4 后新加的注解，从 RestController 类源码可以看出 @RestController 是 @Controller 和 @ResponseBody 两个注解的结合体。

> @Controller=@RestController+@ResponseBody
> 如下 @RestController 的源码可以看出他们的关系

```java
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Controller
@ResponseBody
public @interface RestController {
    @AliasFor(
        annotation = Controller.class
    )
    String value() default "";
}
```

#### @Controller 与 @RestController应用场景

- @Controller 一般应用在有返回界面的应用场景下.

  例如，管理后台使用了 thymeleaf 作为模板开发，需要从后台直接返回 Model 对象到前台，那么这时候就需要使用 @Controller 来注解。

- @RestController 如果只是接口，那么就用 RestController 来注解.

  例如前端页面全部使用了 Html、Jquery来开发，通过 Ajax 请求服务端接口，那么接口就使用 @RestController 统一注解。

#### @RequestMapping 说明

首先我们来看看 @RequestMapping 的源码,

```java
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Mapping
public @interface RequestMapping {
    String name() default "";

    //指定请求的实际地址
    @AliasFor("path")
    String[] value() default {};
    @AliasFor("value")
    String[] path() default {};
    //指定请求的method类型， GET、POST、PUT、DELETE等
    RequestMethod[] method() default {};
    //指定request中必须包含某些参数值是，才让该方法处理。
    String[] params() default {};
    //指定request中必须包含某些指定的header值，才能让该方法处理请求。
    String[] headers() default {};
    //指定处理请求的提交内容类型（Content-Type），例如application/json, text/html;
    String[] consumes() default {};
    //指定返回的内容类型，仅当request请求头中的(Accept)类型中包含该指定类型才返回；
    String[] produces() default {};
}
```

**示例说明：**

| 示例                                                         | 说明                                                         |
| ------------------------------------------------------------ | :----------------------------------------------------------- |
| @RequestMapping("/index")                                    | 默认为 GET 方法的路由 /index                                 |
| @RequestMapping(value="/index",method = RequestMethod.GET)   | 同上面一条                                                   |
| @RequestMapping(value="/add",method = RequestMethod.POST)    | 路由为 /add 的 POST 请求                                     |
| @RequestMapping(value="/add",method = RequestMethod.POST),consumes="application/json" | 路由为 /add 的 POST 请求，但仅仅处理 application/json 的请求 |
| @RequestMapping(value="/add",method = RequestMethod.POST),produces="application/json" | 路由为 /add 的 POST 请求，强调返回为 JSON 格式               |
| @RequestMapping(value="/add",method = RequestMethod.POST),params="myParam=xyz" | 路由为 /add 的 POST 请求，但仅仅处理头部包括 myParam=xyz 的请求 |
| @RequestMapping(value="/add",method = RequestMethod.POST),headers="Referer=http://www.xyz.com/" | 路由为 /add 的 POST 请求，但仅仅处理 来源为 www.xyz.com 的请求 |

#### @Controller 和 @RestController 示例

本章节，将对两个注解配合其他注解编写一系列示例，为了演示 @Controller 返回对应页面功能，我们在示例中引入了 thymeleaf 模板。具体在 pom.xml 中有说明。

| 编号 | 路由          | Http方法 | 方法说明                   |
| ---- | :------------ | :------- | :------------------------- |
| 1    | /user/index   | GET      | 获取用户列表并返回列表页面 |
| 1    | /user/add     | GET      | 用户新增页面               |
| 1    | /user/save    | POST     | 新增用户的api              |
| 1    | /user/edit    | GET      | 用户编辑的页面             |
| 1    | /user/update  | POST     | 编辑用户的api              |
| 1    | /user/del     | GET      | 删除用户页面               |
| 1    | /user/deleted | POST     | 删除用户页面的api          |

## 3、 Thymeleaf 介绍

#### 片段表达式

Thymeleaf中的表达式有好几种

- 变量表达式： `${...}`
- 选择变量表达式： `*{...}`
- 消息表达： `#{...}`
- 链接 URL 表达式： `@{...}`
- 片段表达式： `~{...}`

#### 片段表达式

片段表达式(FragmentExpression)： `~{...}`，片段表达式可以用于引用公共的目标片段比如footer或者header

比如在`/WEB-INF/templates/footer.html`定义一个片段，名为copy。`<div th:fragment="copy">`

```html
<!DOCTYPE html>

<html xmlns:th="http://www.thymeleaf.org">

  <body>

    <div th:fragment="copy">
      &copy; 2011 The Good Thymes Virtual Grocery
    </div>

  </body>

</html>
```

在另一template中引用该片段`<div th:insert="~{footer :: copy}"></div>`

```html
<body>

  ...

  <div th:insert="~{footer :: copy}"></div>

</body>
```

#### 片段表达式语法：

1. **~{templatename::selector}**，会在`/WEB-INF/templates/`目录下寻找名为`templatename`的模版中定义的`fragment`，如上面的`~{footer :: copy}`
2. **~{templatename}**，引用整个`templatename`模版文件作为`fragment`
3. **~{::selector} 或 ~{this::selector}**，引用来自同一模版文件名为`selector`的`fragmnt`

其中`selector`可以是通过`th:fragment`定义的片段，也可以是类选择器、ID选择器等。

当`~{}`片段表达式中出现`::`，则`::`后需要有值，也就是`selector`。

### 预处理

语法：`__${expression}__`

官方文档对其的解释：

> 除了所有这些用于表达式处理的功能外，Thymeleaf 还具有*预处理*表达式的功能。
>
> **预处理是在正常表达式之前完成的表达式的执行**，允许修改最终将执行的表达式。
>
> 预处理的表达式与普通表达式完全一样，但被双下划线符号（如`__${expression}__`）包围。

个人感觉这是出现SSTI最关键的一个地方，预处理也可以解析执行表达式，也就是说找到一个可以控制预处理表达式的地方，让其解析执行我们的payload即可达到任意代码执行



## 4、模板注入demo

我们以spring boot + Thymeleaf模板创建一个带有漏洞的项目。核心代码如下

```
    @GetMapping("/path")
    public String path(@RequestParam String lang) {
        return  lang ; //template path is tainted
    }
```

代码含义如下：用户请求的url为path，参数名称为lang，则服务器通过Thymeleaf模板，去查找相关的模板文件。

例如，用户通过get请求`/path?lang=en`，则服务器去自动拼接待查找的模板文件名，为`resources/templates/en.html`，并返回给用户的浏览器。

上面的代码存在两个问题： 1. 是不是存在任意文件读取？ 2. 是不是存在诸如模板注入的漏洞？？？

PS： pom.xml文件如下所示,**最新的版本该问题已经修复**

```xml
 <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <!--latest-->
        <version>2.2.0.RELEASE</version>
    </parent>
<dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

    </dependencies>
```

### 正常访问URL

正常访问该url，出现http500 ，因为后台没有对应的en模板，所以报错，这个正常。

![image-20221030222130014](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221030222130014.png)

### 异常注入访问

当访问的URL为 `/path2?lang=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22whoami%22).getInputStream()).next()%7d__::.x `

发现出现了模板注入的情况

![image-20221030222335827](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221030222335827.png)

####   调试看看后台是否如何变化的

1、在`org.springframework.web.servlet.DispatcherServlet#doDispatch `下个断点

`DispatcherServlet`的作用

看下DispatcherServlet在Spring MVC中的位置，所有的请求经过DispatcherServlet进行分发，然后根据不通过的对象通过对应的处理方法进行处理：

![image-20221031093255101](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031093255101.png)



初始化的过程:

```java
	protected void initStrategies(ApplicationContext context) {
		initMultipartResolver(context);
		initLocaleResolver(context);
		initThemeResolver(context);
		initHandlerMappings(context);
		initHandlerAdapters(context);
		initHandlerExceptionResolvers(context);
		initRequestToViewNameTranslator(context);
		initViewResolvers(context);
		initFlashMapManager(context);
	}
```

DispatcherServlet 处理请求的规则：

- 在请求中查找并绑定 WebApplicationContext，它可以作为参数被控制器中的方法使用。 默认绑定到 DispatcherServlet.WEB_APPLICATION_CONTEXT_ATTRIBUTE 对应的值。
- 区域解析器 (LocaleResolver) 也绑定到请求上，它可以在请求解析、呈现视图、准备数据等过程中将信息解析为当前的区域环境。如果无需解析这些信息，可以不用管它。
- 主题解析器用来决定使用哪个主题。 如果你不使用主题，可以忽略掉它。
- 如果在应用中声明了 multipart file resolver，则会对请求进行 multipart 检查；如果发现了 multiparts，请求会被包装成 MultipartHttpServlet 来进行处理。
- 如果返回模型，则会解析并返回视图。 如果没有返回模型（由于其他处理程序拦截了请求，可能出于安全原因），则不会返回视图，因为可能已经有响应返回给客户端了。

WebApplicationContext 中声明的 HandlerExceptionResolver bean 可以解析请求处理时抛出的异常。 可以给异常解析器进行特定的配置来解决特定的异常。

DispatcherServlet 还支持返回最后修改日期。 DispatcherServlet 扫描注册的映射关系并，判断找到的处理程序是否实现了 LastModified 接口。 如果实现了，则将 LastModified 接口的 long getLastModified（request）方法的返回值返回给客户端。

2、`org.springframework.web.servlet.DispatcherServlet#doDispatch` doDispatch 方法

在DispatcherServlet  的doDispatch 中通过HandlerAdapter 的handle 方法来处理请求

![image-20221031095307357](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031095307357.png)

3、在HandlerAdapter 中通过调用 ModelAndView handle方法进行处理

![image-20221031095844101](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031095844101.png)

4、接下来调用RequestMappingHandlerAdapter#invokeHandlerMethod 通过反射的方法来处理请求

此时传入的request为 前台请的URI

![image-20221031100125347](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031100125347.png)

在invokeHandlerMethod 方法中接着通过invokeAndHandle 方法处理请求的传入的URL参数

![image-20221031100614504](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031100614504.png)

5、接下来通过调用`org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod#invokeAndHandle`来处理

ServletInvocableHandlerMethod  调用该方法并通过其中一个配置的HandlerMethodReturnValueHandler处理返回值，传入参数：

Params:
webRequest – the current request mavContainer – the ModelAndViewContainer for this request providedArgs – "given" arguments matched by type (not resolved)

通过invokeForRequest 方法获取对应的请求的URL参数

![image-20221031100947954](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031100947954.png)

6、获取到returnValue的值后，通过调用returnValueHandlers.handleReturnValue 先来获取用来处理returnValue值得handle方法

 然后在handleReturnValue  中调用invokeHanderMethod方法来进行处理，接着调用RequestMappingHandlerAdapter的 getModelAndView 来处理，处理完成后返回对应的ModelAndView实例

![image-20221031102737288](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031102737288.png)![image-20221031102752039](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031102752039.png)

7、RequestMappingHandlerAdapter 的handleInternal 方法中更新对应的ModelAndView 的view内容，即对应模板的名称值

![image-20221031110410646](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031110410646.png)

8、ModelAndView mv  通过mv = ha.handle(processedRequest, response, mappedHandler.getHandler()); 获取对应当view内容

上述在handle中调用的一连串的方法，也仅仅是为了获取对应的view内容。

![image-20221031111337284](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031111337284.png)

9、获取到ModelAndView  对应的view内容后，在DispatchServlet中通过 processDispatchResult 来进行下一步的处理

在返回来看下这个DispatchServlet的处理内容大概就比较有感觉了，上述处理在第九步的，返回了view的内容。

![image-20221031111713506](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031111713506.png)

10. DispatcherServlet 通过render 渲染9步骤返回的view

    ![image-20221031194737859](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031194737859.png)

    11. 在render中调用，org.thymeleaf.spring5.view.ThymeleafView#renderFragment，并且通过pareseExpression处理viewTemplateName 模板的名称，并且给viewTemplateName 的名称加上了`~{ }`表达式的处理标志符号![](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031195955755.png)

   12. 在StandardExpressionParser中进行对应的表达式的处理，通过SpringEl表达式处理该模板的名称

       ![image-20221031201049309](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031201049309.png)

![image-20221031201234266](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031201234266.png)

13、后续就不在分析了，后面的处理逻辑就是通render发现 该名称的模板不存在，就报错返回到前台

![image-20221031201409290](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031201409290.png)

14、至此整体的流程分析完毕。



## 5、修复方案

0x01 配置 `@ResponseBody` 或者 `@RestController`

这样 spring 框架就不会将其解析为视图名，而是直接返回, 不再调用模板解析。

```java
@GetMapping("/safe/fragment")
@ResponseBody
public String safeFragment(@RequestParam String section) {
    return "welcome :: " + section; //FP, as @ResponseBody annotation tells Spring to process the return values as body, instead of view name
}
```

0x02 在返回值前面加上 “redirect:”

这样不再由 Spring ThymeleafView来进行解析，而是由 RedirectView 来进行解析。

```java
@GetMapping("/safe/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url; //FP as redirects are not resolved as expressions
}
```

0x03 在方法参数中加上 HttpServletResponse 参数

由于controller的参数被设置为HttpServletResponse，Spring认为它已经处理了HTTP Response，因此不会发生视图名称解析。

```java
@GetMapping("/safe/doc/{document}")
public void getDocument(@PathVariable String document, HttpServletResponse response) {
    log.info("Retrieving " + document); //FP
}
```







### 新版本的修改：

1、在org.thymeleaf.spring5.view.ThymeleafView#renderFragment 中添加了SpringRequestUtils.checkViewNameNotInRequest(viewTemplateName, request);

![image-20221031203848841](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031203848841.png)

```java
public final class SpringRequestUtils {
    public static void checkViewNameNotInRequest(String viewName, HttpServletRequest request) {
        String vn = StringUtils.pack(viewName);
        if (containsExpression(vn)) {
            boolean found = false;
            String requestURI = StringUtils.pack(UriEscape.unescapeUriPath(request.getRequestURI()));
            if (requestURI != null && containsExpression(requestURI)) {
                found = true;
            }

            if (!found) {
                Enumeration<String> paramNames = request.getParameterNames();

                while(!found && paramNames.hasMoreElements()) {
                    String[] paramValues = request.getParameterValues((String)paramNames.nextElement());

                    for(int i = 0; !found && i < paramValues.length; ++i) {
                        String paramValue = StringUtils.pack(paramValues[i]);
                        if (paramValue != null && containsExpression(paramValue) && vn.contains(paramValue)) {
                            found = true;
                        }
                    }
                }
            }

            if (found) {
                throw new TemplateProcessingException("View name contains an expression and so does either the URL path or one of the request parameters. This is forbidden in order to reduce the possibilities that direct user input is executed as a part of the view name.");
            }
        }
    }
```

判断如果存在注入则抛出异常

在老版本该地方并不存在校验

![image-20221031204434099](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221031204434099.png)



# 参考：

1、[java 安全开发之 spring boot Thymeleaf 模板注入 (seebug.org)](https://paper.seebug.org/1332/)

2、[Spring Boot Web 开发@Controller @RestController 使用教程 - fishpro - 博客园 (cnblogs.com)](https://www.cnblogs.com/fishpro/p/spring-boot-study-restcontroller.html)

3、[4.5 片段 · Using Thymeleaf 译文 (gitbooks.io)](https://raledong.gitbooks.io/using-thymeleaf/content/Chapter4/section4.5.html)































