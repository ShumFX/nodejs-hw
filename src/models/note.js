import { Schema, model } from 'mongoose';

const noteSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
    },
    content: {
      type: String,
      required: false,
      default: '',
    },
    tag: {
      type: String,
      required: false, // Змінено на false, бо є default
      enum: ['Work', 'Personal', 'Meeting', 'Shopping', 'Ideas', 'Travel', 'Finance', 'Health', 'Important', 'Todo'],
      default: 'Todo',
    }
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export const Note = model('Note', noteSchema);
