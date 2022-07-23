package routes

import (
	"github.com/gofiber/fiber/v2"
	"go-auth-2/controllers"
)

func Setup(app *fiber.App) {

	app.Post("/api/registration", controllers.Registration)
	app.Post("/api/login", controllers.Login)
	app.Get("/api/user", controllers.User)
	app.Post("/api/logout", controllers.Logout)
	app.Get("/", controllers.Hello)

}
