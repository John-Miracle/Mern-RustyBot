import { Router } from 'express';
import { verifyToken } from '../utils/token-manager.js';
import { chatCompletionValidator, validate } from '../utils/validators.js';
import { deleteChats, generateChatCompletion, sendChatsToUser } from '../controllers/chat-controllers.js';
const chatRoutes = Router();
//Get Response from OpenAI
chatRoutes.post("/new", validate(chatCompletionValidator), verifyToken, generateChatCompletion);
//Send the chats to user
chatRoutes.get("/all-chats", verifyToken, sendChatsToUser);
//Send the chats to user
chatRoutes.delete("/delete", verifyToken, deleteChats);
export default chatRoutes;
//# sourceMappingURL=chat-routes.js.map