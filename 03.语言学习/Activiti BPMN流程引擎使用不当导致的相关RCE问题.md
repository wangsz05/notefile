# 说明
此篇文章主要记录Activiti流程引擎在使用过程中，使用不当会造成的相关问题以及RCE方法，此篇仅做安全研究用，无用相关的攻击，否则后果自负。
# 1.Activiti说明
## 1.1 **概念**
工作流。通过计算机对业务流程自动化执行管理，主要解决的是“使在多个参与者之间按照某种预定义的规则自动进行传递文档、信息或任务的过程，从而实现某个预期的业务目标，或者促使此目标的实现”。
## 1.2 相关的说明
具体的activiti的相关说明参考如下的链接：[Activiti工作流](Activiti工作流)
https://blog.csdn.net/Mr_97xu/article/details/112899079
## 1.3 流程引擎配置类
流程引擎配置类（ProcessEngineConfiguration），通过 ProcessEngineConfiguration 可以创建工作流引擎 ProceccEngine。
**工作流引擎的创建**
工作流引擎的创建主要有两种方式：默认创建方式和一般创建方式
**默认创建方式**
```java
ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();
System.out.println(processEngine);
```
**一般创建方式**
```java
//使用自定义方式创建
ProcessEngineConfiguration processEngineConfiguration = ProcessEngineConfiguration.createProcessEngineConfigurationFromResource("activiti.cfg.xml");
//获取流程引擎对象:通过 ProcessEngineConfiguration 创建 ProcessEngine,此时会创建数据库
ProcessEngine processEngine = processEngineConfiguration.buildProcessEngine();
```
当创建好工作流引擎后，对应的数据库中会自动生成25张数据库表。
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/0455fd2703485e01290f007213d421b5.png)

ACT_GE_PROPERTY中会先展示下一次流程的ID（next.dbid），并且在下一次流程部署的时候，对下一次流程的ID进行赋值。
![image.png](http://moonsec.top/articlepic/b9a3d72abf272075f9ddf894fca4abaa.png)
## 1.4 Activiti表说明
这里以表名的前缀进行说明：
![image.png](http://moonsec.top/articlepic/06412ab55b4c07e02ad2b1ec5e054e65.png)
Service服务接口
Activiti中还有许多的Service服务接口。这些Service 是工作流引擎提供用于进行工作流部署、执行、管理的服务接口，我们可以使用这些接口操作服务对应的数据表。

**Service创建方式**
通过ProcessEngine创建Service方式：
```java
Runtimeservice runtimeService = processEngine.getRuntimeService();
RepositoryService repositoryService = processEngine.getRepositoryService();
TaskService taskService = processEngine.getTaskService();
```
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/3c3a7377d2ce02601d30fc5b788765cb.png)

**RepositoryService**

Activiti 的资源管理类，提供了管理和控制流程发布包和流程定义的操作。使用工作流建模工具设计的业务流程图需要使用此service将流程定义文件的内容部署到计算机。除了部署流程定义以外，还可以查询引擎中的发布包和流程定义。暂停或激活发布包，对应全部和特定流程定义。暂停意味着它们不能再执行任何操作了，激活是对应的反向操作。获得多种资源，像是包含在发布包里的文件，或引擎自动生成的流程图。获得流程定义的pojo版本，可以用来通过java解析流程，而不必通过xml。

**Runtimeservice**
Activiti的流程运行管理类。可以从这个服务类中获取很多关于流程执行相关的信息

**Taskservice**
Activiti的任务管理类。可以从这个类中获取任务的信息。

**Historyservice**
Activiti的历史管理类，可以查询历史信息，执行流程时，引擎会保存很多数据（根据配置)，比如流程实例启动时间，任务的参与者，完成任务的时间，每个流程实例的执行路径，等等。这个服务主要通过查询功能来获得这些数据。

**ManagementService**
Activiti的引擎管理类，提供了对Activiti流程引擎的管理和维护功能，这些功能不在工作流驱动的应用程序中使用，主要用于Activiti 系统的日常维护。
## 1.5 流程符号、画流程图
可以通过idea 的BPMN 插件来进行绘制。
![image.png](http://moonsec.top/articlepic/04078af46000cbe3970e293936317bce.png)

## 1.6 流程的操作
### 1.6.1 部署流程
使用 Activiti 提供的 API 把流程图的内容写入到数据库中
属于资源操作类，使用 RepositoryService
单文件部署：把bpmn文件和png文件逐个处理
压缩包部署：把bpmn文件和png文件打成压缩包来处理
部署操作表：act_re_deployment、act_re_procdef、act_ge_bytearray
```java
/**
 * 流程部署
 */
public void deployment() {
    // 创建 ProcessEngine
    ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();
    // 获取 RepositoryService
    RepositoryService repositoryService = processEngine.getRepositoryService();
    // 使用 service 进行流程的部署,定义一个流程的名字,把bpmn和png部署到数据中
    Deployment deployment = repositoryService.createDeployment()
            .name("出差申请流程")	//流程图标的名字
            .addClasspathResource("bpmn/evection.bpmn")	//bpmn文件
            .addClasspathResource("bpmn/evection.png")	//bpmn文件生成的图片
            .deploy();
    // 输出部署信息
    System.out.println("流程部署ID:" + deployment.getId());
    System.out.println("流程部署名字:" + deployment.getName());
}
```
操作的数据库表：
act_ge_bytearray、act_ge_property、act_re_deployment、act_re_procdef
### 1.6.2 启动流程实例
流程部署完成以后，需要启动流程实例。使用 RuntimeService 根据流程定义的 key进行启动。
核心代码：

```java
/**
 * 启动流程
 */
public void starProcess() {
    // 创建 ProcessEngine
    ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();
    // 获取 RunTimeService
    RuntimeService runtimeService = processEngine.getRuntimeService();
    // 根据流程定义的ID启动流程
    ProcessInstance instance = runtimeService.startProcessInstanceByKey("myEvection");
    // 输出内容
    System.out.println("流程定义ID:" + instance.getProcessDefinitionId());
    System.out.println("流程实例的ID:" + instance.getId());
    System.out.println("当前活动的ID:" + instance.getActivityId());
}
```
### 1.6.3 任务查询
使用 TaskService ，根据流程定义的 key ，任务负责人来进行查询
核心代码：
```java
/**
 * 查询个人待执行的任务
 */
@Test
public void findPersonalTaskList() {
    // 获取流程引擎
    ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();
    // 获取TaskService
    TaskService taskService = processEngine.getTaskService();
    // 根据流程的key和任务的负责人去查询任务
    List<Task> taskList = taskService.createTaskQuery()
            .processDefinitionKey("myEvection")  // 流程的key
            .includeProcessVariables()
            .taskAssignee("zhangsan")           // 要查询的负责人
            .list();
    // 输出
    for (Task task : taskList) {
        System.out.println("流程实例的ID：" + task.getProcessInstanceId());
        System.out.println("任务的ID：" + task.getId());
        System.out.println("任务的负责人：" + task.getAssignee());
        System.out.println("任务的名称：" + task.getName());
    }
}
```
### 1.6.4 任务完成
使用 TaskService ，用任务 ID 直接完成任务。
核心代码：
```java
/**
 * 完成个人任务
 */
@Test
public void completTask() {
    String key = "testCandidiate";
    String assignee = "张三1";	//任务的负责人
    ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();
    TaskService taskService = processEngine.getTaskService();
    Task task = taskService.createTaskQuery()
            .processDefinitionKey(key)
            .taskAssignee(assignee)
            .singleResult();
    if (task != null) {
        taskService.complete(task.getId());
    }
}
```

# 2. Activiti 的漏洞点
实际上使用Activiti的场景主要有2中情况：
1、产品根据业务需求使用bpmn进行开发，最终发的时候内置bpmn在发布包中，不允许用户自行定义。
2、产品使用提供Activiti的通用能力，运行用在产品上自己编辑定义bpmn流程，并执行该流程。
一般来说，第1中情况不存在问题，下面主要套路第2种情况。
Activiti涉及到的漏洞点有主要以下几种：
- **ScriptTask： ScriptTaskActivityBehavior中使用ScriptEngine**


# 3. Activiti的漏洞点
## 3.1 ScriptTask
ScriptTast看相关的bpmn配置demo如下：
```xml
 <process id="hireProcessWithJpa" name="Developer Hiring" isExecutable="true">
    <startEvent id="sid-E0DD2D8E-0672-4BE0-97A4-933DD8771EFF"/>
    <scriptTask id="sid-6b441d89-8564-4069-bb06-fbce3cb9da37" name="scriptTest" scriptFormat="js" activiti:resultVariable="a">
      <script>a=java.lang.Runtime.getRuntime().exec('calc')</script>
    </scriptTask>
    <sequenceFlow id="sid-228a0741-8bf0-4603-9d25-19943b3917d8" sourceRef="sid-E0DD2D8E-0672-4BE0-97A4-933DD8771EFF" targetRef="sid-6b441d89-8564-4069-bb06-fbce3cb9da37"/>
    <endEvent id="sid-90bb0d22-d2d4-4eb6-9a6d-b23f2cdc8688"/>
    <sequenceFlow id="sid-71f0cd02-3d3a-45e2-98a3-349ccec4b3e5" sourceRef="sid-6b441d89-8564-4069-bb06-fbce3cb9da37" targetRef="sid-90bb0d22-d2d4-4eb6-9a6d-b23f2cdc8688"/>
  </process>
```
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/50f7aec93097c9d7418fd81fed14fa73.png)
触发漏洞的点在于：
```xml
    <scriptTask id="sid-6b441d89-8564-4069-bb06-fbce3cb9da37" name="scriptTest" scriptFormat="js" activiti:resultVariable="a">
      <script>a=java.lang.Runtime.getRuntime().exec('calc')</script>
    </scriptTask>
```

bpmn触发的接口类如下：
```java
    @RequestMapping(value = "/start-hire-process", method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public void startHireProcess(@RequestBody Map<String, String> data) {

        Applicant applicant = new Applicant(data.get("name"), data.get("email"), data.get("phoneNumber"));
        applicantRepository.save(applicant);

        Map<String, Object> vars = Collections.<String, Object>singletonMap("applicant", applicant);
        runtimeService.startProcessInstanceByKey("hireProcessWithJpa", vars);
        System.out.println("process finish");
    }
```
具体代码可以参考最后的git工程。

首先执行下该漏洞，同过接口调用，执行的结果如下：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/946a2c29ca9e702cbd7b614639b951ab.png)

### 3.1.1 相关的调试
首先看下相关的漏洞调用链。
在ScriptTaskActivityBehavior的scriptingEngines.evaluate(script, language, execution, storeScriptVariables) 打上断点接可查看全部的调用链过程。
整体的调用链如下：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/83af309db84879187478558b93485aac.png)
### 3.1.3 调用链分析
1、通过 runtimeService.startProcessInstanceByKey 调用bpmn的xml配置文件，启新的流程实例。
runtimeService 是一个接口类，
![image.png](http://moonsec.top/articlepic/0bcf193eeb88ba1bbfadb15715b01d72.png)
在实现类中调用commandExecutor.execute 来执行
![image.png](http://moonsec.top/articlepic/fe62bcffcd0ec965fd5d65f3b2ad8eec.png)
2、commandExecutor 也是一个接口类，最终会调用SpringTransactionInterceptor的execute方法
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/3848d278acff84770161b23daac34d84.png)
在execute方法方法中先初始化TransactionTemplate，然后通过编程事务模板管理来进行处理该流程。这么做的好处是，如果事务处理过程中遇到问题可以进行全面的回滚，将所有的状态回滚到开始的状态。
具体的编程式事务：可以参考https://blog.csdn.net/qq_33404395/article/details/83377382
3、接下来，通过CommandContextInterceptor中的execute方法执行
next.execute(config, command)
在此处的command为processDefinitionKey，即定义的bpmn的xml中的流程key。
4、然后调用TransactionContextInterceptor方法中的exec，调用TransactionContextInterceptor的目的是为了创建TransactionContext事务，用该事务，保存
ontext.getCommandContext()的变量信息，方便出错时候的回滚
![image.png](http://moonsec.top/articlepic/33f3e0af683386ca380446b5b80bc43a.png)
5、上述的2次事务的创建方法完成后，后续进入真正的bpmn的执行流程。
CommandInvoker中调用executeOperations方法，该方法通过while循环读取bpmn的操作节点信息
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/88e1ee03fe142d4dea84b4717ba0c6d1.png)
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/bbca55f23d3263d33250d161345d99f0.png)
6、通过DeployCmd的execute 方法来部署该流程
![image.png](http://moonsec.top/articlepic/0d088baa26c2f52ead1b2041740aad4b.png)
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/26b3f790506431ca2c41e15ff6423cbf.png)
7、在DeploymentManager的deploy方法中逐个节点去部署
![image.png](http://moonsec.top/articlepic/ee6077395393fa82f49cb2279cc6d48f.png)
实际上部署的节点过程是通过BpmnDeployer的 createLocalizationValues方法来创建各个节点
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/b240b86b3a6b85f3b37338c17e4a7ef9.png)
8、在DefaultListableBeanFactory中将执行环境中所有的bean都进行初始化
![image.png](http://moonsec.top/articlepic/8412966869b70fd1b701fbc8287caf45.png)
9、在CommandInvoker中调用executeOperation run方法，在该方法中调用continueThroughFlowNode方法来执行各个节点
![image.png](http://moonsec.top/articlepic/7fe02a641f4c3cc6f035bd90553ec650.png)
10、在ContinueProcessOperation中获取currentelement节点信息
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/877ea37c759a6d13c19d9e669863e7d4.png)
11、在ContinueProcessOperation中通过executeSynchronous 来同步执行节点
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/cb2b0bfbf6b135d4a6aae215bfa8b462.png)
12、ContinueProcessOperation中通过executeActivityBehavior 来执行 bpmn中xml中的scriptTask节点
![image.png](http://moonsec.top/articlepic/713e6a33cf0ab4ca258bf608ab7b2986.png)
13、最终在ScriptTaskActivityBehavior中执行该脚本
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/f2a59089f5ebf8baa469458373198f65.png)
调用的是ScriptingEngines的eval方法。
14、至此scripttask执行完成
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/d00cac0e28a1ec4d11cdcd2994d6bf33.png)

上述记录了scriptTask的全部流程。
PS：调试过程中发现activiti的流程比较长，对activiti的整体了解不够，写的内容可能会有问题，此篇先做流程的记录，后续使用过程中发现问题在同步刷新。

## 3.2 serviceTask 
对应的相关配置
![image.png](http://moonsec.top/articlepic/86067f5a910cf1372b51edecae97d429.png)
执行结果如下：
![image.png](http://moonsec.top/articlepic/3931ddd2c7fbf21d00acf8b0e96669eb.png)
调试对应的调用栈
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/f0188ddc987300020985979ff400d948.png)
1、 在ContinueProcessOperation的executeActivityBehavior中执行xml中设置的serviceTask中定义的activiti class->org.activiti.engine.impl.bpmn.behavior.ShellActivityBehavior
![image.png](http://moonsec.top/articlepic/3969f66b140fe50e4d475860e5b0239b.png)
为啥会在executeActivitiBehavior，可以参考 3.1的 12步骤“12、ContinueProcessOperation中通过executeActivityBehavior 来执行 bpmn中xml中的scriptTask节点”
2、在ClassDelegate中调用 activityBehaviorInstance.execute(execution);方法
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/a7abf84007ad9fff21e71ecb7ca4d52a.png)
3、直接调用了ShellActivityBehavior的exec方法，
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/aa92794a8c7c95da0cefc1753fefb407.png)
直接在该类的execute方法中执行命令，
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/785a79a0fc0604f1b82c65e136b73d09.png)
直接传递进去该类的三个参数，然后通过反射实例化进行运行。
![image.png](http://moonsec.top/articlepic/70f620b29406c47ad82671d8b15fff71.png)

## 3.2 TaskListener 方法
![image.png](http://moonsec.top/articlepic/cfa3a645220e4783151788e206f7f877.png)
## 3.3 executionListener 方法
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/2c191518407cf260a80be0257829b80a.png)
## 3.4 expression 方法
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/b1abb3fa270ab9b034583337313a968a.png)

# 相关的调试代码
https://github.com/wangsz05/LearnDemo