import createHttpError from 'http-errors';
import { Note } from '../models/note.js';

export const getAllNotes = async (req, res) => {

  const { page = 1, perPage = 10, tag, search } = req.query;

  const skip = (page - 1) * perPage;

  function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  const filter = {userId: req.user._id};

  if (search && search.trim() !== "") {
    const safeSearch = escapeRegex(search.trim());
    const regex = new RegExp(safeSearch, "i");
    filter.$or = [{ title: regex }, { content: regex }];
  }

  if (tag) {
    filter.tag = tag;
  }

  const [totalNotes, notes] = await Promise.all([
    Note.countDocuments(filter),
    Note.find(filter).skip(skip).limit(Number(perPage))
  ]);

  const totalPages = Math.ceil(totalNotes / perPage);

    res.status(200).json({
      page,
      perPage,
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
