using Erfa.Api;
var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("ocelot.json", false, true);

var app = builder
    .ConfigureServices()
    .ConfigurePipeline();

app.Run();



public partial class Program { }