/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph


/**
 * 把添加machine到定时任务执行连起来
 * 
 */
predicate machine(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1,Method me1 |
      me.getName() = "addMachine" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma.getAnArgument() and
      me1.getName()="fetchOnce" and 
      ma1.getMethod() = me1 and 
      ma1.getAnArgument() = expDest.asExpr()
      )
}


/**
 * 把添加machine到每个MachineInfo调用自身方法连起来
 */
predicate machine1(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1,Method me1 |
      me.getName() = "addMachine" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma.getAnArgument() and    
      me1.getQualifiedName().matches("%MachineInfo%") and 
      me1.getName().matches("%get%") and
      ma1.getMethod() = me1 and 
      expDest.asExpr() = ma1
      )
}


predicate machine2(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1,Method me1 |
      me.getName() = "getMachines" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma and
      me1.getQualifiedName().matches("%MachineInfo%") and 
      me1.getName().matches("%get%") and
      ma1.getMethod() = me1 and 
      expDest.asExpr() = ma1
      )
}

// predicate machine2(DataFlow::Node expSrc, DataFlow::Node expDest) {
//   exists(MethodAccess ma, Method me |
//       me.getName() = "addMachine" and
//       me = ma.getMethod() and 
//       expSrc.asExpr() = ma.getAnArgument() and
//       expDest.asExpr() = ma.getAnArgument()
//       )
// }


class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node src) { 
    src instanceof RemoteFlowSource
  }


// override predicate isSink(DataFlow::Node sink) {
//     exists(Method me, MethodAccess ma| me.getName() = "execute" and ma.getMethod() = me and 
//     ma.getAnArgument() = sink.asExpr())
//   }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall call,Class clz|
      call.getAnArgument() = sink.asExpr() and call.getConstructedType()=clz and clz.getName()="HttpGet")
  }


  // override predicate isSink(DataFlow::Node sink) {
  //   exists(Method method, MethodAccess call |
  //     method.hasName("execute") and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.apache.http.impl.nio.client", "CloseableHttpAsyncClient") and call.getMethod() = method
  //     and
  //     sink.asExpr() = call.getArgument(0)
  //   )
  // }

  override predicate isAdditionalTaintStep(DataFlow::Node expSrc, DataFlow::Node expDest) {
    exists(MethodAccess ma, Method me, MethodAccess maa,Method mee |
     // me.getQualifiedName().matches("%MachineInfo%") and 
      me.getName()="setIp" and
      ma.getMethod() = me and 
      expSrc.asExpr() = ma.getAnArgument() and
    //  mee.getQualifiedName().matches("%MachineInfo%") and 
      mee.getName().matches("getIp") and
      maa.getMethod() = mee and 
      expDest.asExpr() = maa 
      )
    }
}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
