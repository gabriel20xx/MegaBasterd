package com.tonikelope.megabasterd;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import org.bytedeco.javacv.FFmpegFrameGrabber;
import org.bytedeco.javacv.Frame;
import org.bytedeco.javacv.Java2DFrameConverter;

public class Thumbnailer {

    public Thumbnailer() {
    }

    public static final int IMAGE_THUMB_SIZE = 250;

    public static final float SECONDS_BETWEEN_FRAMES_PERC = 0.03f; //Take frame video at 3% position

    public String createThumbnail(String filename) {
        try {
            if (MiscTools.isVideoFile(filename)) {
                return createVideoThumbnail(filename);
            } else if (MiscTools.isImageFile(filename)) {
                return createImageThumbnail(filename);
            }
        } catch (Exception ex) {
        }
        return null;
    }

    private String createImageThumbnail(String filename) {
        try {
            BufferedImage imagen_original = ImageIO.read(new File(filename));
            if (imagen_original.getHeight() <= IMAGE_THUMB_SIZE) {
                return filename;
            }
            int h = IMAGE_THUMB_SIZE;
            int w = Math.round((((float) imagen_original.getWidth()) * h) / imagen_original.getHeight());
            BufferedImage newImage = new BufferedImage(w, h, imagen_original.getType());
            Graphics2D g = newImage.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            g.drawImage(imagen_original, 0, 0, w, h, null);
            g.dispose();
            File file = File.createTempFile("megabasterd_thumbnail_" + MiscTools.genID(20), ".png");
            ImageIO.write(newImage, "png", file);
            return file.getAbsolutePath();
        } catch (Exception ex) {
            Logger.getLogger(Thumbnailer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private String createVideoThumbnail(String filename) {
        try (FFmpegFrameGrabber grabber = new FFmpegFrameGrabber(filename)) {
            grabber.start();
            long duration = grabber.getLengthInTime();
            long targetTime = (long) (duration * SECONDS_BETWEEN_FRAMES_PERC);
            grabber.setTimestamp(targetTime);
            Frame frame = grabber.grabImage();
            if (frame == null) {
                grabber.setTimestamp(0);
                frame = grabber.grabImage();
            }
            if (frame != null) {
                Java2DFrameConverter converter = new Java2DFrameConverter();
                BufferedImage image = converter.convert(frame);
                if (image != null) {
                    File file = File.createTempFile("megabasterd_thumbnail_" + MiscTools.genID(20), ".jpg");
                    ImageIO.write(image, "jpg", file);
                    return file.getAbsolutePath();
                }
            }
        } catch (Exception ex) {
            Logger.getLogger(Thumbnailer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
