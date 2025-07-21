import userModel from "../models/userModel.js"
import FormData from "form-data"
import axios from "axios"

export const generateImage = async (req, res) => {
    try {
        console.log('generateImage called. req.userId:', req.userId, 'prompt:', req.body.prompt);
        // console.log("BODY:", req.body); // Debug log
        const { prompt } = req.body;

        console.log('userId:', req.userId, 'typeof:', typeof req.userId);
        const allUsers = await userModel.find();
        console.log('All user IDs:', allUsers.map(u => u._id.toString()));
        const user = await userModel.findById(req.userId);

        if (!user || !prompt) {
            return res.json({ success: false, message: "Missing Details" });
        }

        if (user.creditBalance === 0 || user.creditBalance < 0) {
            return res.json({ success: false, message: "Not enough credits", creditBalance: user.creditBalance });
        }

        const formData = new FormData();
        formData.append('prompt', prompt);

        const { data } = await axios.post('https://clipdrop-api.co/text-to-image/v1', formData, {
            headers: {
                'x-api-key': process.env.CLIPDROP_API,
                ...formData.getHeaders()
            },
            responseType: 'arraybuffer'
        });

        const base64Image = Buffer.from(data, 'binary').toString('base64');
        const resultImage = `data:image/png;base64,${base64Image}`;

        await userModel.findByIdAndUpdate(user._id, { creditBalance: user.creditBalance - 1 });

        res.json({ success: true, message: "Image generated successfully", creditBalance: user.creditBalance - 1, resultImage });

    } catch (error) {
        console.log(error.message);
        res.json({ success: false, message: error.message });
    }
}
