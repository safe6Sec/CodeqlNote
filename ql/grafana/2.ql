import go


from Function fun,CallExpr call
where  fun.hasQualifiedName("github.com/grafana/grafana/pkg/api/routing.RouteRegister",
 ["Get","Post","Delete","Put","Patch","Any"]) and call.getTarget() = fun

select fun.getAReference(),call.getAnArgument().toString()