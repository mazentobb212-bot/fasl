export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Test the API
    if (url.pathname === "/api/health") {
      return Response.json({
        success: true,
        message: "FASL API is working! 🇪🇬"
      });
    }

    // Home response
    return Response.json({
      success: true,
      app: "FASL",
      message: "أهلاً بيك في الفصل 😂🇪🇬"
    });
  }
};
