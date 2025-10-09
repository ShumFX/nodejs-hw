import createHttpError from 'http-errors';
import { Note } from '../models/note.js';

export const getAllNotes = async (req, res) => {
  const { page = 1, perPage = 10, tag, search } = req.query;
  const skip = (page - 1) * perPage;

  function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Базовий запит з userId
  let notesQuery = Note.find().where('userId').equals(req.user._id);
  let countQuery = Note.find().where('userId').equals(req.user._id);

  // Фільтрація за tag
  if (tag) {
    notesQuery = notesQuery.where('tag').equals(tag);
    countQuery = countQuery.where('tag').equals(tag);
  }

  // Пошук за title або content
  if (search && search.trim() !== "") {
    const safeSearch = escapeRegex(search.trim());
    const regex = new RegExp(safeSearch, "i");
    
    notesQuery = notesQuery.or([
      { title: regex },
      { content: regex }
    ]);
    
    countQuery = countQuery.or([
      { title: regex },
      { content: regex }
    ]);
  }

  // Виконання запитів
  const [totalNotes, notes] = await Promise.all([
    countQuery.countDocuments(),
    notesQuery.skip(skip).limit(Number(perPage)).sort({ createdAt: -1 })
  ]);

  const totalPages = Math.ceil(totalNotes / perPage);

  res.status(200).json({
    page: Number(page),
    perPage: Number(perPage),
    totalNotes,
    totalPages,
    notes,
  });
};

export const getNoteById = async (req, res, next) => {
  const { noteId } = req.params;

  const note = await Note.findOne({
    _id: noteId,
    userId: req.user._id,
  });

  if (!note) {
    next(createHttpError(404, 'Note not found'));
    return;
  }

  res.status(200).json(note);
};

export const createNote = async (req, res) => {
  const note = await Note.create({
    ...req.body,
    userId: req.user._id,
  });
  res.status(201).json(note);
};

export const deleteNote = async (req, res, next) => {
  const { noteId } = req.params;
  const note = await Note.findOneAndDelete({
    _id: noteId,
    userId: req.user._id,
  });

  if (!note) {
    next(createHttpError(404, "Note not found"));
    return;
  }

  res.status(200).send(note);
};

export const updateNote = async (req, res, next) => {
  const { noteId } = req.params;

  const note = await Note.findOneAndUpdate(
    { _id: noteId, userId: req.user._id },
    req.body,
    { new: true },
  );

  if (!note) {
    next(createHttpError(404, 'Note not found'));
    return;
  }

  res.status(200).json(note);
};
