/**
 * @name Tainttrack Context lookup
 * @description  from https://mp.weixin.qq.com/s/JYco8DysQNszMohH6zJEGw
 * @kind path-problem
 * 
 */

import java
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

class Context extends RefType {
  Context() {
    this.hasQualifiedName("javax.naming", "Context")
    or
    this.hasQualifiedName("javax.naming", "InitialContext")
    or
    this.hasQualifiedName("org.springframework.jndi", "JndiCallback")
    or
    this.hasQualifiedName("org.springframework.jndi", "JndiTemplate")
    or
    this.hasQualifiedName("org.springframework.jndi", "JndiLocatorDelegate")
    or
    this.hasQualifiedName("org.apache.shiro.jndi", "JndiCallback")
    or
    this.getQualifiedName().matches("%JndiCallback")
    or
    this.getQualifiedName().matches("%JndiLocatorDelegate")
    or
    this.getQualifiedName().matches("%JndiTemplate")
  }
}

class Logger extends RefType {
  Logger() { this.hasQualifiedName("org.apache.logging.log4j.spi", "AbstractLogger") }
}

class LoggerInput extends Method {
  LoggerInput() {
    this.getDeclaringType() instanceof Logger and
    this.hasName("error") and
    this.getNumberOfParameters() = 1
  }

  Parameter getAnUntrustedParameter() { result = this.getParameter(0) }
}

predicate isLookup(Expr arg) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "lookup" and
    ma.getMethod().getDeclaringType() instanceof Context and
    arg = ma.getArgument(0)
  )
}

class TainttrackLookup extends TaintTracking::Configuration {
  TainttrackLookup() { this = "TainttrackLookup" }

  override predicate isSource(DataFlow::Node source) {
    exists(LoggerInput LoggerMethod | source.asParameter() = LoggerMethod.getAnUntrustedParameter())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    exists(MethodAccess ma, MethodAccess ma2 |
      ma.getMethod()
          .getDeclaringType()
          .hasQualifiedName("org.apache.logging.log4j.core.impl", "ReusableLogEventFactory") and
      ma.getMethod().hasName("createEvent") and
      fromNode.asExpr() = ma.getArgument(5) and
      ma2.getMethod()
          .getDeclaringType()
          .hasQualifiedName("org.apache.logging.log4j.core.config", "LoggerConfig") and
      ma2.getMethod().hasName("log") and
      ma2.getMethod().getNumberOfParameters() = 2 and
      toNode.asExpr() = ma2.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Expr arg |
      isLookup(arg) and
      sink.asExpr() = arg
    )
  }
}

from TainttrackLookup config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "unsafe lookup", source.getNode(), "this is user input"
