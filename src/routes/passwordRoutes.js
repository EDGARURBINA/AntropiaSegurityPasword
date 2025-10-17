
import express from 'express';
import { PasswordController } from '../controllers/passwordController.js';

const router = express.Router();


router.post('/evaluate', PasswordController.evaluatePassword);

router.post('/generate', PasswordController.generatePassword);

router.get('/info', PasswordController.getApiInfo);

export default router;