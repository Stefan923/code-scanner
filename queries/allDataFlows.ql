import java
import semmle.code.java.dataflow.TaintTracking

class AllTaintConfig extends TaintTracking::Configuration {
  AllTaintConfig() { this = "AllTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getParameter" and
      ma.getMethod().getDeclaringType().getName() = "HttpServletRequest" and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "executeQuery" and
      source.asExpr() = ma
    )
  }
}

from AllTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select source.getNode(), sink.getNode(), "Tainted data flows from source to sink"
