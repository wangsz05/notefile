## Spring---Bean&Fileter 对象详解

###  说明

在Spring中，对象无需自己查找或创建与其所关联的其他对象（解耦合）。
Spring容器负责创建应用程序中的bean并通过DI来协调Java对象之间的关系。
创建应用对象之间协作关系的行为通常称为装配（wiring），这也是依赖注入（DI）的本质。

总而言之，bean对象就是应用程序中的Java对象，Spring容器创建并封装这些Java对象为容器中的bean对象，在需要时自动注入到变量中，赋予对应Java对象的实例。

### 1.bean
### Spring配置bean的三种方式
**创建bean的方式**

1. 1 通过构造函数创建Java对象对应的bean

1. 无参构造函数（默认构造函数）
2. 带参构造函数
3. 使用普通工厂中的方法创建对象，并存入指定的bean
4. 使用工厂中的静态方法创建对象，并存入指定的bean

**Spring配置bean的三种方式**

- 在XML中进行显式配置。
- 在Java中进行显式配置。
- 隐式的bean发现机制和自动装配。

### 2. 本文以XML中的显式配置介绍bean对象的创建方式、作用范围、生命周期等。

### 2.1 创建bean的方式
**1 通过构造函数创建Java对象对应的bean**
1.1 无参构造函数（默认构造函数）

```xml
<bean id="accountService" class="com.simple.service.impl.AccountServiceImpl" ></bean>
```

如上，通过AccountServiceImpl的默认构造函数创建了AccountServiceImpl实例化的bean对象。在Java代码中定义的 AccountServiceImpl 类或其父类对象变量，会根据变量名对应bean的id自动注入。

1. 2 带参构造函数

    ```xml
    <bean id="accountDao" class="com.simple.Dao.impl.AccountDaoImpl" ></bean>
    
    <bean id="accountService" class="com.simple.service.impl.AccountServiceImpl" >
    	<constructor-arg ref="accountDao"></constructor-arg>
    	<constructor-arg value="#{T(其他各种类型，如string等等)}"></constructor-arg>
    </bean>       
    ```

   accountDao代表在AccountServiceImpl类构造函数中需要注入的Java对象，ref 属性的值为该Java对象对应的bean的id值；#{T}是Spring中的EL表达式，T表示构造函数中带有的其他类型参数（基本类型，如String等等）。

**2 使用普通工厂中的方法创建对象，并存入指定的bean**
使用某个工厂类中的方法创建Java对象，并存入spring容器。

工厂类：

```java
public class InitFactory {
    public IAccountService getAccountService(){
        return new AccountServiceImpl();
    }
}
```

XML配置：

```xml
<bean id="initFactory" class="com.simple.factory.InitFactory"></bean>
<bean id="accountService" factory-bean="initFactory" factory-method="getAccountService"></bean>
```

**3 使用工厂中的静态方法创建对象，并存入指定的bean**
使用某个类中的静态方法创建Java对象，并存入spring容器。由于使用的是工厂中的静态方法，所以不需要实例化工厂。

工厂类：

```java
public class staticFactory {
    public static IAccountService getAccountService(){
        return new AccountServiceImpl();
    }
}
```

XML配置：

```xml
<bean id="accountService" class="com.simple.factory.staticFactory" factory-method="getAccountService"></bean>
上述三种创建bean的方式中，一般使用第1种方法通过构造函数创建bean。
```

### 2.2 bean的作用范围
bean的作用范围由 bean 标签的 scope 属性来指定。其属性值包括：

- 属性值	说明
- singleton	默认值，指定bean为单例的
- prototype	指定bean为多例的
- request	web项目中，作用于request域
- session	web项目中，作用于session域
- global-session	web项目中，作用于集群环境的session域；若不是集群环境，则相当于session
- 一般常用的是 singleton ，即单例的。

单例的bean表示Spring容器中该bean只有一个对应的实例化Java对象；多例的bean表示Spring容器中该bean可以有对应类多个实例化Java对象（可通过其存储地址区分）。

### 2.3 bean对象的生命周期
**1 单例bean**
默认情况下，Spring读取XML配置文件创建Spring容器时bean对象就会被创建
在创建对象时，先执行对象的构造方法，然后调用bean标签的 init-method="..."属性值中指定的方法
在Spring容器销毁时，单例bean随之消亡。bean消亡即对象被销毁时，会调用bean标签的 destroy-method="..."属性值中指定的方法
可以设置bean标签的 lazy-init="true" 使该对象在第一次被访问时才创建
XML配置：创建单例bean，指定init-method="..."和destroy-method="..."属性

```xml
<bean id="accountService" class="com.simple.service.impl.AccountServiceImpl"
	scope="singleton" init-method="init" destroy-method="destory">
</bean>
```

**2.AccountServiceImpl 类：**

```java
public class AccountServiceImpl implements IAccountService {
//默认无参构造器
public AccountServiceImpl() {
    System.out.println("对象已创建！");
}

public void saveAccount() {
    System.out.println("Service中的saveAccount方法执行了！！");
}

//初始时执行方法
public void init(){
    System.out.println("对象初始化了！！！");
}

//销毁时执行方法
public void destory(){
    System.out.println("对象销毁了！！！");
}
}
```


测试单例bean的生命周期：



```java
public class Client {
public static void main(String[] args) {
    //1.获取Spring核心容器对象
    ClassPathXmlApplicationContext ac = new ClassPathXmlApplicationContext("bean.xml");   //bean.xml放在根目录下，所有可以直接写文件名
    //2.根据id获取bean对象
    //可以使用强制类型转换
    //IAccountService as = (IAccountService) ac.getBean("accountService");
    //也可以指定对象类型
    IAccountService as = ac.getBean("accountService",IAccountService.class);
    //查看创建的as对象
    System.out.println(as);

	//执行as对象的方法
    as.saveAccount();

    //手动销毁Spring容器，查看as对象消亡过程
    ac.close();
    System.out.println("结束！");
}
}
```
结果如下：

![image-20220910104847894](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220910104847894.png)

**4 多例bean**
Spring读取XML配置文件创建Spring容器时，不会立刻创建多例bean对应的对象
在每一次访问这个多例bean对应的对象的时，spring容器都会创建该对象,并且调用init-method=".."属性值中所指定的方法
Spring容器销毁时，多例bean对应创建的对象也不会消亡。因为是多例的（该类型的对象可以有多个），所以在Spring容器创建该对象并将它赋予给Java变量后，该对象就由Java的进行管理，销毁该对象也由垃圾回收机制进行回收。spring容器一旦把这个对象交给Java之后,就不再管理这个对象了

## 3 Filter

### 3.1 spring filter关系图

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/12539296-9c06aac347523b1b.jpg)

Spring的web包中中有很多过滤器，这些过滤器位于org.springframework.web.filter并且理所当然地实现了javax.servlet.Filter，不过实现的方式有以下几类：

(1) 直接实现Filter，这一类过滤器只有CompositeFilter；

(2) 继承抽象类GenericFilterBean，该类实现了javax.servlet.Filter，这一类的过滤器只有一个，即DelegatingFilterProxy；

(3) 继承抽象类OncePerRequestFilter，该类为GenericFilterBean的直接子类，这一类过滤器包括CharacterEncodingFilter、HiddenHttpMethodFilter、HttpPutFormContentFilter、RequestContextFilter和ShallowEtagHeaderFilter；

(4) 继承抽象类AbstractRequestLoggingFilter，该类为OncePerRequestFilter的直接子类，这一类过滤器包括CommonsRequestLoggingFilter、Log4jNestedDiagnosticContextFilter和ServletContextRequestLoggingFilter。

本文要讲述的，即是GenericFilterBean、OncePerRequestFilter和AbstractRequestLoggingFilter。

### 3.1 GenericFilterBean

抽象类GenericFilterBean实现了javax.servlet.Filter、org.springframework.beans.factory.BeanNameAware、org.springframework.context.EnvironmentAware、org.springframework.web.context.ServletContextAware、org.springframework.beans.factory.InitializingBean和org.springframework.beans.factory.DisposableBean五个接口，作用如下：

(1) Filter，实现过滤器；

(2) BeanNameAware，**实现该接口的setBeanName方法**，便于Bean管理器生成Bean；
 (3) EnvironmentAware，实现该接口的setEnvironment方法，指明该Bean运行的环境；

(4) ServletContextAware，实现该接口的setServletContextAware方法，指明上下文；

(5) InitializingBean，实现该接口的afterPropertiesSet方法，指明设置属性生的操作；

(6) DisposableBean，实现该接口的destroy方法，用于回收资源。

GenericFilterBean的工作流程是：init-doFilter-destory，其中的init和destory在该类中实现，doFilter在具体实现类中实现。

GenericFilterBean中包含一个内部私有类**FilterConfigPropertyValues**，主要用于将web.xml中定义的init-param的值取出。

### 3.2 OncePerRequestFilter

抽象类oncePerRequestFilter继承自GenericFilterBean，它保留了GenericFilterBean中的所有方法并对之进行了扩展，在oncePerRequestFilter中的主要方法是doFilter。

### 3.3 AbstractRequestLoggingFilter

AbstractRequestLoggingFilter继承了OncePerRequestFilter并实现了其doFilterInternal方法

我们在使用过滤器时，通常没必要知道GenericFilterBean、OncePerRequestFilter和AbstractRequestLoggingFilter，但不防碍我们了解这几个类，就上文所述，
 AbstractRequestLoggingFilter继承自OncePerRequestFilter，
 OncePerRequestFilter继承自GenericFilterBean，
 所以我们知道，genericFilterBean是任何类型的过滤器的一个比较方便的超类，
 这个类主要实现的就是从web.xml文件中取得init-param中设定的值，然后对Filter进行初始化（当然，其子类可以覆盖init方法）。

OncePerRequestFilter继承自GenericFilterBean，那么它自然知道怎么去获取配置文件中的属性及其值，所以其重点不在于取值，而在于确保在接收到一个request后，每个filter只执行一次，它的子类只需要关注Filter的具体实现即doFilterInternal。

AbstractRequestLoggingFilter是对OncePerRequestFilter的扩展，它除了遗传了其父类及祖先类的所有功能外，还在doFilterInternal中决定了在过滤之前和之后执行的事件，它的子类关注的是beforeRequest和afterRequest。

总体来说，这三个类分别执行了Filter的某部分功能，当然，具体如何执行由它们的子类规定，若你需要实现自己的过滤器，也可以根据上文所述继承你所需要的类。

另外Spring代码中有不少抽象工具类，内部只有静态方法，为避免别人误用它来生成实例，将它设计为抽象类，这是设计者的意图。



## 4. Filter过滤器 HandlerInterceptorAdapter拦截器 GenericFilterBean过滤器

### 4.1 Filter

**Filter要使请求继续被处理，就一定要显示调用filterChain.doFilter()**

自定义Filter，@WebFilter形式
@WebFilter形式控制不了多个过滤器之间的执行顺序,默认是按照class名字首字母的ASCII的字母排序.
并且需要在启动类上加上@ServletComponentScan扫描过滤器

```java
package com.fchan.espractice.filter;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@WebFilter(filterName = "tokenFilter", urlPatterns = "/testMybatisTrsanctional/*")
public class TokenFilter implements Filter, ApplicationContextAware {

private ApplicationContext applicationContext;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        String token = request.getHeader("token");
        if(!StringUtils.isEmpty(token)){
            filterChain.doFilter(servletRequest, servletResponse);
        }

        HttpServletResponse response = (HttpServletResponse) servletResponse;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        Map<String,Object> map = new HashMap<>();
        map.put("name","李四");
        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(objectMapper.writeValueAsBytes(map));
        outputStream.close();

    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}

```

**启动类加上扫描注解**

```java
package com.fchan.espractice;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.context.annotation.Bean;
import org.springframework.transaction.PlatformTransactionManager;

@SpringBootApplication
//@SpringBootApplication的作用等价于同时组合使用@EnableAutoConfiguration，@ComponentScan，@SpringBootConfiguration
@MapperScan("com.fchan.espractice.dao")
//ServletComponentScan扫描自定义Filter，可以指定包路径
@ServletComponentScan
public class EsPracticeApplication {

    @Bean
    public Object testBean(PlatformTransactionManager platformTransactionManager){
        System.out.println(">>>>>>>>>>" + platformTransactionManager.getClass().getName());
        return new Object();
    }

    public static void main(String[] args) {
        SpringApplication.run(EsPracticeApplication.class, args);
    }

}

```

### 4.2 Springmvc的HandlerInterceptorAdapter拦截器
在HandlerInterceptorAdapter中主要提供了以下的方法：

preHandle：在方法被调用前执行。在该方法中可以做类似校验的功能。如果返回true，则继续调用下一个拦截器。如果返回false，则中断执行，也就是说我们想调用的方法不会被执行，但是你可以修改response为你想要的响应。
postHandle：在方法执行后调用。
afterCompletion：在整个请求处理完毕后进行回调，也就是说视图渲染完毕或者调用方已经拿到响应。

```java
package com.fchan.espractice.intercept;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@Component
public class GlobalIntercept extends HandlerInterceptorAdapter {

    @Autowired
    private ObjectMapper objectMapper;


    public GlobalIntercept() {
        super();
    }

    /**
     * false拦截
     * true放行
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("token");
        if(!StringUtils.isEmpty(token)){
            return true;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        Map<String,Object> map = new HashMap();
        map.put("name","张三");
        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(objectMapper.writeValueAsBytes(map));
        outputStream.close();
        

        return false;
    }

}

```

**配置拦截器,及顺序说明**
多个拦截器的话按照
`registry.addInterceptor`
的添加顺序来执行

```java
package com.fchan.espractice.intercept.config;

import com.fchan.espractice.intercept.GlobalIntercept;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class InterceptConfig implements WebMvcConfigurer, ApplicationContextAware {

    private ApplicationContext applicationContext;


    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(applicationContext.getBean(GlobalIntercept.class));
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}

```

### 4.3 Spring的GenericFilterBean过滤器

**注：GenericFilterBean的继承可以用于实现接口的参数过滤**

org.springframework.web.filter.GenericFilterBean是spring对Servelet的Filter的实现，我们继承GenericFilterBean后可以将Servelet的Filter纳入spring的容器中作为bean;

@Order(-999)数值越小执行优先级越高

自定义的过滤器

```java
package com.fchan.espractice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@Order(-999)
public class MySpringFilter extends GenericFilterBean {

    @Autowired
    private ObjectMapper objectMapper;


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        String token = request.getHeader("token");
        if(!StringUtils.isEmpty(token)){
            filterChain.doFilter(servletRequest, servletResponse);
        }

        HttpServletResponse response = (HttpServletResponse) servletResponse;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        Map<String,Object> map = new HashMap<>();
        map.put("name","李四");
        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(objectMapper.writeValueAsBytes(map));
        outputStream.close();
    }
}

```

在重复一次GenericFilterBean说明：

抽象类GenericFilterBean实现了javax.servlet.Filter、org.springframework.beans.factory.BeanNameAware、org.springframework.context.EnvironmentAware、org.springframework.web.context.ServletContextAware、org.springframework.beans.factory.InitializingBean和org.springframework.beans.factory.DisposableBean五个接口，作用如下：

(1) Filter，实现过滤器；

(2) BeanNameAware，**实现该接口的setBeanName方法**，便于Bean管理器生成Bean；
 (3) EnvironmentAware，实现该接口的setEnvironment方法，指明该Bean运行的环境；

(4) ServletContextAware，实现该接口的setServletContextAware方法，指明上下文；

(5) InitializingBean，实现该接口的afterPropertiesSet方法，指明设置属性生的操作；

(6) DisposableBean，实现该接口的destroy方法，用于回收资源。

GenericFilterBean的工作流程是：init-doFilter-destory，其中的init和destory在该类中实现，doFilter在具体实现类中实现。

GenericFilterBean中包含一个内部私有类**FilterConfigPropertyValues**，主要用于将web.xml中定义的init-param的值取出。









## 参考

1、https://blog.csdn.net/weixin_43944305/article/details/119892613

2、https://www.jianshu.com/p/ce4a5614d22f

