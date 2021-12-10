/**
 * @kind path-problem
 */

import go
import DataFlow::PathGraph


class GfSource extends DataFlow::Node {
    GfSource(){
        exists( Function fun| 
            fun.hasQualifiedName("github.com/grafana/grafana/pkg/api/routing.RouteRegister",
        ["Get","Post","Delete","Put","Patch","Any"]) and 
          //["Get","Post"]) and 
        fun.getAReference()=this.asExpr()
        )
    }
}


class Gfconfig extends TaintTracking::Configuration{

    Gfconfig() { this = "Gfconfig" }

    override predicate isSource(DataFlow::Node source) {
        source instanceof GfSource
    }
  
    override predicate isSink(DataFlow::Node sink) {
        exists(Function fun ,CallExpr call| 
            fun.hasQualifiedName("os", "Open") and 
        call.getTarget() = fun and 
        call.getAnArgument()= sink.asExpr()
        )
    }

    /**
     * sink参数只能是两个，第二个参数才是真正的sink
     */
    override predicate isAdditionalTaintStep(DataFlow::Node expSrc, DataFlow::Node expDest) {
      exists(CallExpr call|
        call=expSrc.asExpr()  and 
        call.getArgument(0).getType().toString()="string" and
        call.getNumArgument()=2 and
        call.getArgument(1).(CallExpr).getTarget().getAParameter()=expDest.asParameter()
        )
      }
  }

from Gfconfig gf,DataFlow::PathNode source,DataFlow::PathNode sink
where gf.hasFlowPath(source, sink)
select source.getNode(), source, sink, "test"