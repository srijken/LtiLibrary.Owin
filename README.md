LTI OWIN Library
================
[![Build status](https://ci.appveyor.com/api/projects/status/rk9dnw8ahmxrvtjx?svg=true
)](https://ci.appveyor.com/project/srijken/ltilibrary.owin) 

There are two .NET projects in this solution to support IMS LTI Tool Providers and Tool Consumers.

## LtiLibrary.Owin.Security.Lti
This library depends on LtiLibrary.Core and implements OWIN middleware for LTI. This is useful if you are using OWIN middleware to authenticate your web application and want to add LTI authentication.

Available on NuGet: https://www.nuget.org/packages/LtiLibrary.Owin.Security.Lti

## LtiLibrary.AspNet.Identity.Owin
This library depends on both LtiLibrary.Owin.Security.Lti and LtiLibrary.Core. It provides ASP.NET application support for the OWIN middleware for LTI.

Available on NuGet: https://www.nuget.org/packages/LtiLibrary.AspNet.Identity.Owin
